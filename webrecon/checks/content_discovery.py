"""Content / directory discovery — probe a wordlist of common paths.

Complements the sensitive-file probe with broader endpoint discovery (admin
panels, API docs, dashboards, backups). Newly found paths widen the attack
surface for the other checks and the report.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from webrecon.checks.base import Check
from webrecon.core.config import Config
from webrecon.core.crawler import CrawlData
from webrecon.core.http_client import HttpClient
from webrecon.core.target import Target
from webrecon.data import load_lines
from webrecon.model.finding import Finding
from webrecon.model.severity import Severity

# Paths whose exposure is notable enough to raise a finding (not just 200s).
_INTERESTING = ("admin", "manager", "phpmyadmin", "adminer", "actuator",
                "console", "swagger", "api-docs", "openapi", "graphql",
                "debug", "backup", "server-status", "wp-admin", "wp-login",
                "config", "setup", "install", "phpinfo", "info.php")


class ContentDiscoveryCheck(Check):
    name = "content"
    description = "Directory/content discovery of common sensitive paths."

    def run(self, target: Target, http: HttpClient, crawl: CrawlData,
            config: Config) -> list[Finding]:
        paths = load_lines("wordlists/content-discovery.txt")

        def probe(path: str):
            resp = http.get(target.url(path), allow_redirects=False)
            if resp is None:
                return None
            # Reachable (200) or auth-gated (401/403) both reveal the endpoint.
            if resp.status_code in (200, 401, 403):
                return path, resp.status_code
            return None

        hits: list[tuple[str, int]] = []
        with ThreadPoolExecutor(max_workers=max(10, config.threads)) as pool:
            for fut in as_completed([pool.submit(probe, p) for p in paths]):
                r = fut.result()
                if r:
                    hits.append(r)

        findings: list[Finding] = []
        for path, code in hits:
            if not any(k in path.lower() for k in _INTERESTING):
                continue
            gated = code in (401, 403)
            findings.append(Finding(
                id="CONTENT-001",
                title=f"Discovered {'auth-gated ' if gated else ''}endpoint: /{path}",
                severity=Severity.LOW if gated else Severity.MEDIUM,
                owasp="A05:2021 - Security Misconfiguration", cwe="CWE-538",
                cvss=3.1 if gated else 5.0, location=target.url(path),
                confidence="CONFIRMED",
                description=f"The path /{path} returned HTTP {code} — a sensitive "
                            "endpoint is present"
                            + (" (auth required)." if gated else " and reachable."),
                evidence=f"HTTP {code}",
                impact="Admin/API/debug surfaces are attacker targets; verify "
                       "authentication and access control.",
                remediation="Restrict access, require strong auth, or remove the "
                            "endpoint from production.",
                poc=f"curl -i '{target.url(path)}'",
                references=["https://cwe.mitre.org/data/definitions/538.html"]))
        return findings

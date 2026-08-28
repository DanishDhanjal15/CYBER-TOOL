"""Probe robots.txt / sitemap.xml and a small sensitive-file wordlist.

Returns (info, findings). A reachable secret/config file is reported at a
severity matching its sensitivity.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from webrecon.core.http_client import HttpClient
from webrecon.core.target import Target
from webrecon.data import load_lines
from webrecon.model.finding import Finding
from webrecon.model.severity import Severity


# Files whose mere presence is high-impact (credentials / source disclosure).
_HIGH_RISK = {".env", ".git/config", ".git/HEAD", "wp-config.php", "wp-config.php.bak",
              "config.php.bak", "config.php~", "id_rsa", ".htpasswd", "backup.sql",
              "db.sql", "dump.sql", "database.yml", "settings.py"}


def _looks_present(resp) -> bool:
    if resp is None:
        return False
    if resp.status_code != 200:
        return False
    body = resp.text or ""
    # Filter out soft-404 pages that return 200 with an error body.
    lowered = body[:400].lower()
    if "not found" in lowered or "404" in lowered and len(body) < 600:
        return False
    return len(body.strip()) > 0


def gather(target: Target, http: HttpClient, *, threads: int = 12
           ) -> tuple[dict, list[Finding]]:
    info: dict = {"robots": None, "sitemap": None, "exposed_files": []}
    findings: list[Finding] = []

    robots = http.get(target.url("/robots.txt"))
    if robots is not None and robots.status_code == 200:
        info["robots"] = robots.text[:2000]
    sitemap = http.get(target.url("/sitemap.xml"))
    if sitemap is not None and sitemap.status_code == 200:
        info["sitemap"] = "present"

    wordlist = load_lines("wordlists/sensitive-files.txt")

    def probe(path: str):
        resp = http.get(target.url(path))
        return path, resp

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(probe, p) for p in wordlist]
        for fut in as_completed(futures):
            path, resp = fut.result()
            if _looks_present(resp):
                info["exposed_files"].append(path)
                findings.append(_exposed_finding(target, path, resp))

    return info, findings


def _exposed_finding(target: Target, path: str, resp) -> Finding:
    high = path in _HIGH_RISK
    sev = Severity.HIGH if high else Severity.MEDIUM
    return Finding(
        id="FILE-001",
        title=f"Sensitive file exposed: /{path}",
        severity=sev,
        owasp="A05:2021 - Security Misconfiguration",
        cwe="CWE-538",
        cvss=7.5 if high else 5.3,
        location=target.url(path),
        description=f"The path /{path} is publicly reachable and returned HTTP "
                    f"{resp.status_code}.",
        evidence=(resp.text or "")[:200].replace("\n", " "),
        impact=("May disclose credentials, source code, or configuration that "
                "aids further attacks." if high else
                "May disclose configuration or metadata useful to an attacker."),
        remediation="Remove the file from the web root or block access via "
                    "server config; rotate any leaked secrets.",
        references=["https://cwe.mitre.org/data/definitions/538.html"],
    )

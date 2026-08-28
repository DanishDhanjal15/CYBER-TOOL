"""Reflected XSS detection using a unique unencoded marker."""
from __future__ import annotations

from webrecon.checks.base import Check
from webrecon.checks._inject import enumerate_points, send, build_poc
from webrecon.core.config import Config
from webrecon.core.crawler import CrawlData
from webrecon.core.http_client import HttpClient
from webrecon.core.target import Target
from webrecon.data import load_lines
from webrecon.model.finding import Finding
from webrecon.model.severity import Severity


# A distinctive marker; if it appears unencoded in the HTML, it reflected raw.
_MARKER = "wr9xzq"


class ReflectedXssCheck(Check):
    name = "xss"
    description = "Reflected cross-site scripting in parameters/forms."

    def run(self, target: Target, http: HttpClient, crawl: CrawlData,
            config: Config) -> list[Finding]:
        findings: list[Finding] = []
        seen_points: set[str] = set()
        payloads = [p.replace("WRXSS", _MARKER) for p in load_lines("payloads/xss.txt")]

        for point in enumerate_points(crawl):
            key = f"{point.url}|{point.param}"
            if key in seen_points:
                continue
            for payload in payloads:
                resp = send(http, point, payload)
                if resp is None:
                    continue
                body = resp.text or ""
                # Reflected raw (marker inside an unencoded tag/attribute).
                if _MARKER in body and ("<" + _MARKER in body.lower()
                                        or _MARKER + ">" in body.lower()
                                        or "onerror=" + _MARKER in body.lower()
                                        or "onload=" + _MARKER in body.lower()):
                    seen_points.add(key)
                    findings.append(Finding(
                        id=f"XSS-{len(findings)+1:03d}",
                        title=f"Reflected XSS in '{point.param}'",
                        severity=Severity.HIGH,
                        owasp="A03:2021 - Injection", cwe="CWE-79",
                        cvss=6.1, location=point.url,
                        description=f"Input in '{point.param}' is reflected into "
                                    "the HTML response without encoding.",
                        evidence=f"payload={payload!r} reflected unencoded",
                        impact="An attacker can run arbitrary JavaScript in the "
                               "victim's browser (session theft, defacement).",
                        remediation="Context-aware output encoding; validate "
                                    "input; add a Content-Security-Policy.",
                        poc=build_poc(point, payload),
                        references=["https://cwe.mitre.org/data/definitions/79.html"]))
                    break
        return findings

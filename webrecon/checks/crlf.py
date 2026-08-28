"""CRLF injection / HTTP response splitting detection."""
from __future__ import annotations

from webrecon.checks.base import Check
from webrecon.checks._inject import enumerate_points, send, build_poc
from webrecon.core.config import Config
from webrecon.core.crawler import CrawlData
from webrecon.core.http_client import HttpClient
from webrecon.core.target import Target
from webrecon.model.finding import Finding
from webrecon.model.severity import Severity


_MARKER = "wrcrlf"
# Payloads that, if unfiltered, inject a new response header.
_PAYLOADS = [
    f"%0d%0aX-WR-Inject:%20{_MARKER}",
    f"%0aX-WR-Inject:%20{_MARKER}",
    f"\r\nX-WR-Inject: {_MARKER}",
]


class CrlfInjectionCheck(Check):
    name = "crlf"
    description = "CRLF injection / HTTP response splitting."

    def run(self, target: Target, http: HttpClient, crawl: CrawlData,
            config: Config) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for point in enumerate_points(crawl):
            key = f"{point.url}|{point.param}"
            if key in seen:
                continue
            for payload in _PAYLOADS:
                resp = send(http, point, payload)
                if resp is None:
                    continue
                # Did our injected header appear in the response headers?
                if resp.headers.get("X-WR-Inject", "").strip() == _MARKER:
                    seen.add(key)
                    findings.append(Finding(
                        id=f"CRLF-{len(findings)+1:03d}",
                        title=f"CRLF injection in '{point.param}'",
                        severity=Severity.HIGH, owasp="A03:2021 - Injection",
                        cwe="CWE-93", cvss=6.5, location=point.url,
                        confidence="CONFIRMED",
                        description=f"Input in '{point.param}' can inject CR/LF and "
                                    "add arbitrary response headers.",
                        evidence=f"payload={payload!r} added X-WR-Inject header",
                        impact="HTTP response splitting: header injection, cache "
                               "poisoning, and reflected XSS.",
                        remediation="Strip CR/LF from user input used in headers/"
                                    "redirects.",
                        poc=build_poc(point, payload),
                        references=["https://cwe.mitre.org/data/definitions/93.html"]))
                    break
        return findings

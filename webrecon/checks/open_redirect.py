"""Detect open redirects in parameters that look redirect-related."""
from __future__ import annotations

from urllib.parse import urlparse

from webrecon.checks.base import Check
from webrecon.checks._inject import enumerate_points, send, build_poc
from webrecon.core.config import Config
from webrecon.core.crawler import CrawlData
from webrecon.core.http_client import HttpClient
from webrecon.core.target import Target
from webrecon.model.finding import Finding
from webrecon.model.severity import Severity


_REDIRECT_PARAMS = ("redirect", "url", "next", "return", "returnurl", "returnto",
                    "dest", "destination", "continue", "goto", "r", "u", "target")
_EVIL = "https://webrecon-evil.example/pwned"


class OpenRedirectCheck(Check):
    name = "openredirect"
    description = "Open redirect via redirect-style parameters."

    def run(self, target: Target, http: HttpClient, crawl: CrawlData,
            config: Config) -> list[Finding]:
        findings: list[Finding] = []
        points = [p for p in enumerate_points(crawl)
                  if p.param.lower() in _REDIRECT_PARAMS]
        for idx, point in enumerate(points, start=1):
            resp = send(http, point, _EVIL)
            if resp is None:
                continue
            location = resp.headers.get("Location", "")
            if resp.status_code in (301, 302, 303, 307, 308) and \
                    urlparse(location).netloc == "webrecon-evil.example":
                findings.append(Finding(
                    id=f"REDIR-{idx:03d}",
                    title=f"Open redirect via '{point.param}'",
                    severity=Severity.MEDIUM,
                    owasp="A01:2021 - Broken Access Control", cwe="CWE-601",
                    cvss=6.1, location=point.url,
                    description=f"The '{point.param}' parameter redirects to an "
                                "attacker-controlled absolute URL.",
                    evidence=f"payload={_EVIL} -> Location: {location}",
                    impact="Enables convincing phishing and can bypass some "
                           "referer-based protections.",
                    remediation="Allow only relative paths or an allowlist of "
                                "destinations; never redirect to raw user input.",
                    poc=build_poc(point, _EVIL),
                    references=["https://cwe.mitre.org/data/definitions/601.html"]))
        return findings

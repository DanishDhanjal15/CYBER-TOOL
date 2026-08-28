"""Host header injection detection (password-reset poisoning, cache issues)."""
from __future__ import annotations

from webrecon.checks.base import Check
from webrecon.core.config import Config
from webrecon.core.crawler import CrawlData
from webrecon.core.http_client import HttpClient
from webrecon.core.target import Target
from webrecon.model.finding import Finding
from webrecon.model.severity import Severity


_EVIL = "webrecon-evil.example"


class HostHeaderCheck(Check):
    name = "hostheader"
    description = "Host header injection (reset-link poisoning, cache poisoning)."

    def run(self, target: Target, http: HttpClient, crawl: CrawlData,
            config: Config) -> list[Finding]:
        findings: list[Finding] = []
        url = target.url("/")

        # 1) Malicious Host header reflected in body/links.
        r1 = http.get(url, headers={"Host": _EVIL}, allow_redirects=False)
        if r1 is not None:
            body = (r1.text or "")
            loc = r1.headers.get("Location", "")
            if _EVIL in body or _EVIL in loc:
                findings.append(Finding(
                    id="HOSTHDR-001", title="Host header reflected (injection)",
                    severity=Severity.MEDIUM, owasp="A03:2021 - Injection",
                    cwe="CWE-644", cvss=6.1, location=url, confidence="CONFIRMED",
                    description="A spoofed Host header is reflected into the "
                                "response body or a redirect URL.",
                    evidence=f"Host: {_EVIL} reflected in "
                             + ("Location" if _EVIL in loc else "body"),
                    impact="Password-reset link poisoning, cache poisoning, and "
                           "routing-based attacks.",
                    remediation="Validate Host against an allowlist; build absolute "
                                "URLs from a trusted configured hostname, not the "
                                "request Host.",
                    poc=f"curl -i -H 'Host: {_EVIL}' '{url}'",
                    references=["https://cwe.mitre.org/data/definitions/644.html"]))

        # 2) X-Forwarded-Host override reflected.
        r2 = http.get(url, headers={"X-Forwarded-Host": _EVIL},
                      allow_redirects=False)
        if r2 is not None and (_EVIL in (r2.text or "")
                               or _EVIL in r2.headers.get("Location", "")):
            findings.append(Finding(
                id="HOSTHDR-002", title="X-Forwarded-Host override reflected",
                severity=Severity.MEDIUM, owasp="A03:2021 - Injection",
                cwe="CWE-644", cvss=6.1, location=url, confidence="CONFIRMED",
                description="X-Forwarded-Host is trusted and reflected, enabling "
                            "URL poisoning.",
                evidence=f"X-Forwarded-Host: {_EVIL} reflected",
                impact="Reset-link / cache poisoning via a proxy header.",
                remediation="Ignore untrusted forwarding headers or validate them.",
                poc=f"curl -i -H 'X-Forwarded-Host: {_EVIL}' '{url}'",
                references=["https://cwe.mitre.org/data/definitions/644.html"]))
        return findings

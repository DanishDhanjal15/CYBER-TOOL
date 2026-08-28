"""Flag state-changing forms that lack an anti-CSRF token."""
from __future__ import annotations

from webrecon.checks.base import Check
from webrecon.core.config import Config
from webrecon.core.crawler import CrawlData
from webrecon.core.http_client import HttpClient
from webrecon.core.target import Target
from webrecon.model.finding import Finding
from webrecon.model.severity import Severity


_TOKEN_HINTS = ("csrf", "token", "authenticity", "nonce", "__requestverification",
                "xsrf")


class CsrfCheck(Check):
    name = "csrf"
    description = "POST forms missing an anti-CSRF token."

    def run(self, target: Target, http: HttpClient, crawl: CrawlData,
            config: Config) -> list[Finding]:
        findings: list[Finding] = []
        for idx, form in enumerate(crawl.forms, start=1):
            if form.method != "post":
                continue
            names = " ".join(form.input_names()).lower()
            if any(hint in names for hint in _TOKEN_HINTS):
                continue
            findings.append(Finding(
                id=f"CSRF-{idx:03d}",
                title="POST form without anti-CSRF token",
                severity=Severity.MEDIUM,
                owasp="A01:2021 - Broken Access Control", cwe="CWE-352",
                cvss=5.4, location=form.action,
                description="A state-changing form has no hidden CSRF token "
                            "field.",
                evidence=f"fields: {', '.join(form.input_names()) or '(none)'}",
                impact="An attacker page can submit this form on behalf of a "
                       "logged-in victim.",
                remediation="Add a per-session/per-request CSRF token and verify "
                            "it server-side; use SameSite cookies.",
                references=["https://cwe.mitre.org/data/definitions/352.html"]))
        return findings

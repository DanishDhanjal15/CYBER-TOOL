"""Detect information disclosure: version banners and verbose error stacks."""
from __future__ import annotations

import re

from webrecon.checks.base import Check
from webrecon.core.config import Config
from webrecon.core.crawler import CrawlData
from webrecon.core.http_client import HttpClient
from webrecon.core.target import Target
from webrecon.model.finding import Finding
from webrecon.model.severity import Severity


# Server/X-Powered-By values that include a version number are noteworthy.
_VERSION_RE = re.compile(r"\d+\.\d+")
_STACK_SIGNS = (
    "traceback (most recent call last)", "stack trace:", "exception in thread",
    "fatal error:", "warning: include(", "notice: undefined",
    "java.lang.", "system.web.", "org.apache.", "at java.",
    "microsoft ole db provider", "on line ",
)


class InfoDisclosureCheck(Check):
    name = "infodisclosure"
    description = "Version banners and verbose error/stack disclosure."

    def run(self, target: Target, http: HttpClient, crawl: CrawlData,
            config: Config) -> list[Finding]:
        findings: list[Finding] = []
        resp = http.get(target.url("/"), allow_redirects=True)
        if resp is not None:
            for hdr in ("Server", "X-Powered-By", "X-AspNet-Version",
                        "X-AspNetMvc-Version"):
                val = resp.headers.get(hdr)
                if val and _VERSION_RE.search(val):
                    findings.append(Finding(
                        id="INFO-001",
                        title=f"Software version disclosed in '{hdr}' header",
                        severity=Severity.INFO,
                        owasp="A05:2021 - Security Misconfiguration", cwe="CWE-200",
                        cvss=0.0, location=target.url("/"),
                        description=f"The '{hdr}' header reveals a version: {val}.",
                        evidence=f"{hdr}: {val}",
                        impact="Version info helps attackers match known CVEs.",
                        remediation="Suppress or genericise version banners.",
                        references=["https://cwe.mitre.org/data/definitions/200.html"]))

        # Trigger a likely error page and look for leaked stack traces.
        err = http.get(target.url("/webrecon-nonexistent-%27%22"))
        if err is not None:
            body = (err.text or "").lower()
            hit = next((s for s in _STACK_SIGNS if s in body), None)
            if hit:
                findings.append(Finding(
                    id="INFO-002", title="Verbose error / stack trace disclosure",
                    severity=Severity.LOW,
                    owasp="A05:2021 - Security Misconfiguration", cwe="CWE-209",
                    cvss=3.7, location=err.url,
                    description="An error response leaks internal stack/exception "
                                "details.",
                    evidence=f"matched marker: {hit!r}",
                    impact="Leaks framework internals, file paths, and query "
                           "structure useful for further attacks.",
                    remediation="Return generic error pages; log details "
                                "server-side only.",
                    references=["https://cwe.mitre.org/data/definitions/209.html"]))
        return findings

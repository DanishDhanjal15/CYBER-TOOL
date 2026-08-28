"""Detect dangerous enabled HTTP methods (TRACE, PUT, DELETE, CONNECT)."""
from __future__ import annotations

from webrecon.checks.base import Check
from webrecon.core.config import Config
from webrecon.core.crawler import CrawlData
from webrecon.core.http_client import HttpClient
from webrecon.core.target import Target
from webrecon.model.finding import Finding
from webrecon.model.severity import Severity


_DANGEROUS = {
    "TRACE": (Severity.LOW, "TRACE can enable Cross-Site Tracing (XST)."),
    "PUT": (Severity.HIGH, "PUT may allow uploading arbitrary files."),
    "DELETE": (Severity.HIGH, "DELETE may allow removing server resources."),
    "CONNECT": (Severity.MEDIUM, "CONNECT may allow proxying through the server."),
}


class HttpMethodsCheck(Check):
    name = "methods"
    description = "Dangerous HTTP methods enabled (TRACE/PUT/DELETE/CONNECT)."

    def run(self, target: Target, http: HttpClient, crawl: CrawlData,
            config: Config) -> list[Finding]:
        findings: list[Finding] = []
        url = target.url("/")

        # Prefer an OPTIONS advertisement, then verify individually.
        options = http.request("OPTIONS", url)
        advertised = ""
        if options is not None:
            advertised = options.headers.get("Allow", "")

        for idx, (method, meta) in enumerate(_DANGEROUS.items(), start=1):
            sev, impact = meta
            enabled = False
            evidence = ""
            if method in advertised.upper():
                enabled = True
                evidence = f"OPTIONS Allow: {advertised}"
            else:
                resp = http.request(method, url)
                if resp is not None and resp.status_code not in (
                        400, 401, 403, 405, 501):
                    enabled = True
                    evidence = f"{method} {url} -> HTTP {resp.status_code}"
            if enabled:
                findings.append(Finding(
                    id=f"METHOD-{idx:03d}",
                    title=f"Dangerous HTTP method enabled: {method}",
                    severity=sev,
                    owasp="A05:2021 - Security Misconfiguration", cwe="CWE-650",
                    cvss=7.5 if sev == Severity.HIGH else 3.5, location=url,
                    description=f"The server appears to accept the {method} method.",
                    evidence=evidence, impact=impact,
                    remediation=f"Disable {method} unless explicitly required.",
                    references=["https://cwe.mitre.org/data/definitions/650.html"]))
        return findings

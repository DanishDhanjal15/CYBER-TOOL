"""Check for missing / weak HTTP security response headers."""
from __future__ import annotations

from webrecon.checks.base import Check
from webrecon.core.config import Config
from webrecon.core.crawler import CrawlData
from webrecon.core.http_client import HttpClient
from webrecon.core.target import Target
from webrecon.model.finding import Finding
from webrecon.model.severity import Severity


# header -> (severity, title, impact, remediation)
_HEADERS = {
    "content-security-policy": (
        Severity.MEDIUM, "Missing Content-Security-Policy",
        "Without CSP, injected scripts run freely, worsening XSS impact.",
        "Add a restrictive Content-Security-Policy header."),
    "strict-transport-security": (
        Severity.MEDIUM, "Missing Strict-Transport-Security (HSTS)",
        "Users can be downgraded to HTTP and have traffic intercepted.",
        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."),
    "x-frame-options": (
        Severity.LOW, "Missing X-Frame-Options",
        "The page can be framed, enabling clickjacking.",
        "Add 'X-Frame-Options: DENY' or a CSP frame-ancestors directive."),
    "x-content-type-options": (
        Severity.LOW, "Missing X-Content-Type-Options",
        "Browsers may MIME-sniff responses, enabling some attacks.",
        "Add 'X-Content-Type-Options: nosniff'."),
    "referrer-policy": (
        Severity.LOW, "Missing Referrer-Policy",
        "Full URLs may leak to third parties via the Referer header.",
        "Add 'Referrer-Policy: strict-origin-when-cross-origin'."),
    "permissions-policy": (
        Severity.INFO, "Missing Permissions-Policy",
        "Powerful browser features are not explicitly restricted.",
        "Add a Permissions-Policy header disabling unused features."),
}


class SecurityHeadersCheck(Check):
    name = "headers"
    description = "Missing/weak HTTP security headers (CSP, HSTS, X-Frame, ...)."

    def run(self, target: Target, http: HttpClient, crawl: CrawlData,
            config: Config) -> list[Finding]:
        resp = http.get(target.url("/"), allow_redirects=True)
        if resp is None:
            return []
        present = {k.lower() for k in resp.headers.keys()}
        findings: list[Finding] = []
        for idx, (header, meta) in enumerate(_HEADERS.items(), start=1):
            if header not in present:
                sev, title, impact, fix = meta
                findings.append(Finding(
                    id=f"SEC-HEADERS-{idx:03d}", title=title, severity=sev,
                    owasp="A05:2021 - Security Misconfiguration", cwe="CWE-693",
                    cvss=4.0 if sev == Severity.MEDIUM else 2.0,
                    location=target.url("/"),
                    description=f"The response is missing the '{header}' header.",
                    evidence=f"Response headers: {', '.join(sorted(present))[:180]}",
                    impact=impact, remediation=fix,
                    references=["https://owasp.org/www-project-secure-headers/"],
                ))
        return findings

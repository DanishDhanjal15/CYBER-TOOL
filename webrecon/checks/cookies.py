"""Check cookies for missing HttpOnly / Secure / SameSite attributes."""
from __future__ import annotations

from webrecon.checks.base import Check
from webrecon.core.config import Config
from webrecon.core.crawler import CrawlData
from webrecon.core.http_client import HttpClient
from webrecon.core.target import Target
from webrecon.model.finding import Finding
from webrecon.model.severity import Severity


class CookieFlagsCheck(Check):
    name = "cookies"
    description = "Cookies missing HttpOnly / Secure / SameSite flags."

    def run(self, target: Target, http: HttpClient, crawl: CrawlData,
            config: Config) -> list[Finding]:
        resp = http.get(target.url("/"), allow_redirects=True)
        if resp is None:
            return []
        findings: list[Finding] = []
        # requests exposes raw Set-Cookie via response cookies + headers.
        raw_cookies = resp.raw.headers.getlist("Set-Cookie") \
            if hasattr(resp.raw, "headers") else []
        if not raw_cookies:
            single = resp.headers.get("Set-Cookie")
            raw_cookies = [single] if single else []

        for idx, cookie in enumerate(raw_cookies, start=1):
            lowered = cookie.lower()
            name = cookie.split("=", 1)[0].strip()
            missing = []
            if "httponly" not in lowered:
                missing.append("HttpOnly")
            if target.scheme == "https" and "secure" not in lowered:
                missing.append("Secure")
            if "samesite" not in lowered:
                missing.append("SameSite")
            if not missing:
                continue
            findings.append(Finding(
                id=f"COOKIE-{idx:03d}",
                title=f"Cookie '{name}' missing flags: {', '.join(missing)}",
                severity=Severity.LOW,
                owasp="A05:2021 - Security Misconfiguration", cwe="CWE-1004",
                cvss=3.5, location=target.url("/"),
                description=f"Set-Cookie for '{name}' lacks: {', '.join(missing)}.",
                evidence=cookie[:180],
                impact="Session cookies may be stolen via XSS or sent over "
                       "plaintext / cross-site requests.",
                remediation="Set HttpOnly, Secure (on HTTPS), and an explicit "
                            "SameSite attribute on session cookies.",
                references=["https://owasp.org/www-community/controls/"
                            "SecureCookieAttribute"],
            ))
        return findings

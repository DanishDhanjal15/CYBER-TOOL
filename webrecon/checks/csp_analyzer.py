"""Deep Content-Security-Policy analysis — weaknesses in a *present* CSP.

The security-headers check only reports a missing CSP. This one parses an
existing CSP and flags the ways it can still be bypassed (unsafe-inline,
unsafe-eval, wildcards, missing object/base/frame-ancestors directives).
"""
from __future__ import annotations

from webrecon.checks.base import Check
from webrecon.core.config import Config
from webrecon.core.crawler import CrawlData
from webrecon.core.http_client import HttpClient
from webrecon.core.target import Target
from webrecon.model.finding import Finding
from webrecon.model.severity import Severity


class CspAnalyzerCheck(Check):
    name = "csp"
    description = "Deep analysis of an existing Content-Security-Policy."

    def run(self, target: Target, http: HttpClient, crawl: CrawlData,
            config: Config) -> list[Finding]:
        resp = http.get(target.url("/"), allow_redirects=True)
        if resp is None:
            return []
        csp = resp.headers.get("Content-Security-Policy", "")
        if not csp:
            return []   # 'missing CSP' is handled by the headers check

        low = csp.lower()
        weaknesses: list[str] = []
        if "'unsafe-inline'" in low:
            weaknesses.append("'unsafe-inline' allows inline scripts (XSS not "
                              "mitigated)")
        if "'unsafe-eval'" in low:
            weaknesses.append("'unsafe-eval' permits eval()-based execution")
        if "script-src" in low and ("*" in low.split("script-src", 1)[1][:40]):
            weaknesses.append("wildcard '*' source in script-src")
        if "default-src" not in low and "script-src" not in low:
            weaknesses.append("no default-src/script-src — scripts unrestricted")
        if "object-src" not in low:
            weaknesses.append("no object-src (plugin/flash injection possible)")
        if "base-uri" not in low:
            weaknesses.append("no base-uri (base-tag injection / relative-URL "
                              "hijack)")
        if "frame-ancestors" not in low:
            weaknesses.append("no frame-ancestors (clickjacking not blocked)")
        if "data:" in low and "script-src" in low:
            weaknesses.append("data: scheme allowed for scripts")

        if not weaknesses:
            return []
        sev = (Severity.MEDIUM if any("unsafe-inline" in w or "wildcard" in w
               or "unrestricted" in w for w in weaknesses) else Severity.LOW)
        return [Finding(
            id="CSP-001", title="Weak Content-Security-Policy (bypassable)",
            severity=sev, owasp="A05:2021 - Security Misconfiguration", cwe="CWE-693",
            cvss=5.3 if sev == Severity.MEDIUM else 3.1, location=target.url("/"),
            confidence="CONFIRMED",
            description="A CSP is present but has weaknesses that let attackers "
                        "bypass it.",
            evidence="; ".join(weaknesses[:6]),
            impact="XSS and clickjacking protections are weakened or ineffective.",
            remediation="Remove 'unsafe-inline'/'unsafe-eval', drop wildcards, use "
                        "nonces/hashes, and set object-src 'none', base-uri "
                        "'self', frame-ancestors 'none'.",
            references=["https://cwe.mitre.org/data/definitions/693.html",
                        "https://csp-evaluator.withgoogle.com/"])]

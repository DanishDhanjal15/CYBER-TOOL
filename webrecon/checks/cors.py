"""Detect permissive CORS configuration (reflected / wildcard origin)."""
from __future__ import annotations

from webrecon.checks.base import Check
from webrecon.core.config import Config
from webrecon.core.crawler import CrawlData
from webrecon.core.http_client import HttpClient
from webrecon.core.target import Target
from webrecon.model.finding import Finding
from webrecon.model.severity import Severity


_EVIL_ORIGIN = "https://webrecon-evil.example"


class CorsCheck(Check):
    name = "cors"
    description = "Permissive CORS (wildcard or reflected Origin)."

    def run(self, target: Target, http: HttpClient, crawl: CrawlData,
            config: Config) -> list[Finding]:
        resp = http.get(target.url("/"), headers={"Origin": _EVIL_ORIGIN},
                        allow_redirects=True)
        if resp is None:
            return []
        acao = resp.headers.get("Access-Control-Allow-Origin")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
        if not acao:
            return []

        findings: list[Finding] = []
        if acao == "*":
            findings.append(Finding(
                id="CORS-001", title="Wildcard CORS policy (Access-Control-Allow-Origin: *)",
                severity=Severity.LOW,
                owasp="A05:2021 - Security Misconfiguration", cwe="CWE-942",
                cvss=3.7, location=target.url("/"),
                description="The server allows any origin to read responses.",
                evidence=f"Access-Control-Allow-Origin: {acao}",
                impact="Any website can read responses (higher risk if the "
                       "endpoint returns sensitive data).",
                remediation="Restrict Access-Control-Allow-Origin to a trusted "
                            "allowlist of origins.",
                references=["https://cwe.mitre.org/data/definitions/942.html"]))
        elif acao == _EVIL_ORIGIN:
            sev = Severity.HIGH if acac == "true" else Severity.MEDIUM
            findings.append(Finding(
                id="CORS-002", title="Reflected CORS origin (arbitrary origin trusted)",
                severity=sev,
                owasp="A05:2021 - Security Misconfiguration", cwe="CWE-942",
                cvss=7.1 if sev == Severity.HIGH else 5.4, location=target.url("/"),
                description="The server reflects an attacker-supplied Origin in "
                            "Access-Control-Allow-Origin"
                            + (" WITH credentials allowed." if acac == "true" else "."),
                evidence=f"Origin: {_EVIL_ORIGIN} -> ACAO: {acao}; "
                         f"ACAC: {acac or 'not set'}",
                impact="A malicious site can make authenticated cross-origin "
                       "requests and read the responses.",
                remediation="Never reflect arbitrary origins; validate against an "
                            "allowlist and avoid credentials with wildcard.",
                references=["https://portswigger.net/web-security/cors"]))
        return findings

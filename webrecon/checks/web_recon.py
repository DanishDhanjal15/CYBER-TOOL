"""Quick web-recon wins: security.txt, Subresource Integrity, HTML comments.

Three cheap, high-signal passive checks bundled together:
  * security.txt presence (a disclosure contact — INFO if missing)
  * external <script> tags without an integrity (SRI) attribute
  * HTML comments that leak sensitive keywords (TODO, password, internal…)
"""
from __future__ import annotations

import re

from bs4 import BeautifulSoup

from webrecon.checks.base import Check
from webrecon.core.config import Config
from webrecon.core.crawler import CrawlData
from webrecon.core.http_client import HttpClient
from webrecon.core.target import Target
from webrecon.model.finding import Finding
from webrecon.model.severity import Severity

_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
_SENSITIVE = ("password", "passwd", "todo", "fixme", "hack", "secret", "api key",
              "apikey", "token", "internal", "debug", "username", "backdoor",
              "do not", "temporary", "bug", "disable")


class WebReconCheck(Check):
    name = "webrecon"
    description = "security.txt, missing SRI, and leaky HTML comments."

    def run(self, target: Target, http: HttpClient, crawl: CrawlData,
            config: Config) -> list[Finding]:
        findings: list[Finding] = []
        home = http.get(target.url("/"), allow_redirects=True)
        html = (home.text or "") if home is not None else ""

        # 1) security.txt
        st = http.get(target.url("/.well-known/security.txt"))
        if not (st is not None and st.status_code == 200 and "contact" in
                (st.text or "").lower()):
            findings.append(Finding(
                id="SECTXT-001", title="No security.txt disclosure policy",
                severity=Severity.INFO, owasp="A05:2021 - Security Misconfiguration",
                cwe="", cvss=0.0, location=target.url("/.well-known/security.txt"),
                confidence="CONFIRMED",
                description="No /.well-known/security.txt — researchers have no "
                            "standard way to report vulnerabilities.",
                evidence="security.txt missing or has no Contact field",
                impact="Hinders responsible disclosure (best-practice gap).",
                remediation="Publish /.well-known/security.txt with a Contact and "
                            "Expires field.",
                references=["https://securitytxt.org/"]))

        if not html:
            return findings
        soup = BeautifulSoup(html, "html.parser")

        # 2) Missing SRI on external scripts
        no_sri = []
        for s in soup.find_all("script", src=True):
            src = s["src"]
            if src.startswith(("http://", "https://", "//")) and \
                    not s.get("integrity") and target.host not in src:
                no_sri.append(src)
        if no_sri:
            findings.append(Finding(
                id="SRI-001",
                title="External scripts without Subresource Integrity (SRI)",
                severity=Severity.LOW,
                owasp="A08:2021 - Software & Data Integrity Failures", cwe="CWE-353",
                cvss=3.7, location=target.url("/"), confidence="CONFIRMED",
                description="Third-party scripts are loaded without an 'integrity' "
                            "attribute, so a compromised CDN could inject code.",
                evidence="; ".join(no_sri[:5]),
                impact="Supply-chain script tampering would execute unnoticed.",
                remediation="Add integrity + crossorigin attributes (SRI hashes) "
                            "to external <script>/<link> tags.",
                references=["https://cwe.mitre.org/data/definitions/353.html"]))

        # 3) Sensitive HTML comments
        leaks = []
        for c in _COMMENT_RE.findall(html):
            cl = c.lower()
            hit = next((k for k in _SENSITIVE if k in cl), None)
            if hit:
                leaks.append(c.strip()[:80])
        if leaks:
            findings.append(Finding(
                id="COMMENT-001", title="Sensitive information in HTML comments",
                severity=Severity.LOW, owasp="A05:2021 - Security Misconfiguration",
                cwe="CWE-615", cvss=3.1, location=target.url("/"),
                confidence="CONFIRMED",
                description="HTML comments contain developer notes with sensitive "
                            "keywords.",
                evidence="; ".join(leaks[:4]),
                impact="Leaks internal notes, TODOs, credentials, or logic hints.",
                remediation="Strip developer comments from production HTML.",
                references=["https://cwe.mitre.org/data/definitions/615.html"]))
        return findings

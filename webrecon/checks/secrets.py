"""Passive JavaScript & response secret scanning.

Fetches the target's JavaScript bundles (crawled <script src> + common guess
paths), plus the homepage HTML, and scans them for hard-coded secrets, exposed
source maps, and leaked internal hostnames. Purely passive — it only reads
what the site already serves.
"""
from __future__ import annotations

import re

from webrecon.checks.base import Check
from webrecon.core.config import Config
from webrecon.core.crawler import CrawlData
from webrecon.core.http_client import HttpClient
from webrecon.core.target import Target
from webrecon.data.secret_patterns import (SECRET_PATTERNS, HOST_LEAK_PATTERNS,
                                           JS_GUESS_PATHS)
from webrecon.model.finding import Finding
from webrecon.model.severity import Severity


_SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=([^\s'\"]+)")
_MAX_JS = 40


class SecretsCheck(Check):
    name = "secrets"
    description = "Hard-coded secrets, source maps, internal hosts in JS/responses."

    def run(self, target: Target, http: HttpClient, crawl: CrawlData,
            config: Config) -> list[Finding]:
        findings: list[Finding] = []
        seen_secret: set[str] = set()
        host_hits: set[str] = set()

        # Assemble the set of text sources to scan.
        sources: list[tuple[str, str]] = []
        home = http.get(target.url("/"), allow_redirects=True)
        if home is not None:
            sources.append((target.url("/"), home.text or ""))

        js_urls = list(dict.fromkeys(
            crawl.js_urls + [target.url(p) for p in JS_GUESS_PATHS]))[:_MAX_JS]
        for js in js_urls:
            resp = http.get(js)
            if resp is None or resp.status_code != 200:
                continue
            body = resp.text or ""
            if not body:
                continue
            sources.append((js, body))

            # Source-map exposure (leaks original frontend source).
            if js.endswith(".js"):
                mp = http.get(js + ".map")
                if mp is not None and mp.status_code == 200 and \
                        '"sources"' in (mp.text or "")[:2000]:
                    findings.append(Finding(
                        id="JS-MAP-001",
                        title=f"Exposed JavaScript source map: {js}.map",
                        severity=Severity.MEDIUM,
                        owasp="A05:2021 - Security Misconfiguration", cwe="CWE-540",
                        cvss=5.3, location=js + ".map", confidence="CONFIRMED",
                        description="A .map file exposes the original (pre-minified) "
                                    "source, aiding attackers in finding logic flaws "
                                    "and secrets.",
                        evidence="source map returned 200 with embedded sources",
                        impact="Full frontend source reconstruction.",
                        remediation="Do not deploy .map files to production.",
                        references=["https://cwe.mitre.org/data/definitions/540.html"]))

        # Scan every source for secrets + internal-host leaks.
        for origin, text in sources:
            for name, sev, cwe, rx in SECRET_PATTERNS:
                for m in rx.finditer(text):
                    token = m.group(0)
                    key = f"{name}|{token[:12]}"
                    if key in seen_secret:
                        continue
                    seen_secret.add(key)
                    findings.append(Finding(
                        id="SECRET-001", title=f"Hard-coded secret exposed: {name}",
                        severity=sev, owasp="A05:2021 - Security Misconfiguration",
                        cwe=cwe, cvss=9.1 if sev == Severity.CRITICAL else 6.5,
                        location=origin, confidence="CONFIRMED",
                        description=f"A {name} appears in client-served content.",
                        evidence=f"{token[:6]}…{token[-4:]} (redacted)",
                        impact="Anyone loading the page obtains a live credential; "
                               "may grant access to cloud/API/data.",
                        remediation="Remove the secret from client code, rotate it "
                                    "immediately, and load secrets server-side only.",
                        poc=f"# found in {origin}",
                        references=["https://cwe.mitre.org/data/definitions/798.html"]))
            for name, rx in HOST_LEAK_PATTERNS:
                for m in rx.finditer(text):
                    val = m.group(0)
                    if val in host_hits or val.startswith(("192.168.0.", "127.0")):
                        continue
                    host_hits.add(val)

        if host_hits:
            findings.append(Finding(
                id="JS-LEAK-001", title="Internal hostnames / IPs leaked in JS",
                severity=Severity.LOW,
                owasp="A05:2021 - Security Misconfiguration", cwe="CWE-200",
                cvss=3.7, location=target.base_url, confidence="CONFIRMED",
                description="Client-served JavaScript references internal-only "
                            "hosts/IPs, disclosing internal topology.",
                evidence="; ".join(sorted(host_hits)[:8]),
                impact="Reveals internal network structure useful for later "
                       "attacks.",
                remediation="Strip internal references from production bundles.",
                references=["https://cwe.mitre.org/data/definitions/200.html"]))
        return findings

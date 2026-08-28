"""Path traversal / Local File Inclusion detection."""
from __future__ import annotations

import re

from webrecon.checks.base import Check
from webrecon.checks._inject import enumerate_points, send, build_poc
from webrecon.core.config import Config
from webrecon.core.crawler import CrawlData
from webrecon.core.http_client import HttpClient
from webrecon.core.target import Target
from webrecon.data import load_lines
from webrecon.model.finding import Finding
from webrecon.model.severity import Severity


# Signatures of files we try to read via traversal.
_PASSWD_RE = re.compile(r"root:.*:0:0:")
_WININI_RE = re.compile(r"\[fonts\]|\[extensions\]|for 16-bit app support",
                        re.IGNORECASE)
# Params commonly tied to file inclusion.
_FILE_PARAMS = ("file", "page", "path", "template", "include", "doc", "document",
                "folder", "root", "pg", "style", "view", "content", "name")


class PathTraversalCheck(Check):
    name = "traversal"
    description = "Path traversal / local file inclusion."

    def run(self, target: Target, http: HttpClient, crawl: CrawlData,
            config: Config) -> list[Finding]:
        findings: list[Finding] = []
        payloads = list(load_lines("payloads/traversal.txt"))
        seen: set[str] = set()

        points = enumerate_points(crawl)
        # Prioritise file-ish params; in aggressive mode test everything.
        if not config.aggressive:
            points = [p for p in points if p.param.lower() in _FILE_PARAMS]

        for point in points:
            key = f"{point.url}|{point.param}"
            if key in seen:
                continue
            for payload in payloads:
                resp = send(http, point, payload)
                if resp is None:
                    continue
                body = resp.text or ""
                if _PASSWD_RE.search(body) or _WININI_RE.search(body):
                    seen.add(key)
                    findings.append(Finding(
                        id=f"LFI-{len(findings)+1:03d}",
                        title=f"Path traversal / LFI in '{point.param}'",
                        severity=Severity.HIGH,
                        owasp="A01:2021 - Broken Access Control", cwe="CWE-22",
                        cvss=7.5, location=point.url,
                        description=f"Input in '{point.param}' allowed reading a "
                                    "file outside the web root.",
                        evidence=f"payload={payload!r}; system file content matched",
                        impact="Read arbitrary server files (config, secrets, "
                               "source); may escalate to code execution.",
                        remediation="Resolve and validate paths against an "
                                    "allowlist; reject '../'; avoid using input as "
                                    "a filesystem path.",
                        poc=build_poc(point, payload),
                        references=["https://cwe.mitre.org/data/definitions/22.html"]))
                    break
        return findings

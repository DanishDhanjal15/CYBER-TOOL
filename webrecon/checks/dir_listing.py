"""Detect directory listing (auto-index) enabled on common paths."""
from __future__ import annotations

from webrecon.checks.base import Check
from webrecon.core.config import Config
from webrecon.core.crawler import CrawlData
from webrecon.core.http_client import HttpClient
from webrecon.core.target import Target
from webrecon.model.finding import Finding
from webrecon.model.severity import Severity


_CANDIDATE_DIRS = ["/images/", "/img/", "/uploads/", "/files/", "/assets/",
                   "/backup/", "/static/", "/css/", "/js/", "/data/", "/tmp/"]
_SIGNATURES = ("index of /", "<title>index of", "directory listing for",
               "[to parent directory]")


class DirectoryListingCheck(Check):
    name = "dirlisting"
    description = "Directory listing / auto-index enabled."

    def run(self, target: Target, http: HttpClient, crawl: CrawlData,
            config: Config) -> list[Finding]:
        findings: list[Finding] = []
        for idx, path in enumerate(_CANDIDATE_DIRS, start=1):
            resp = http.get(target.url(path))
            if resp is None or resp.status_code != 200:
                continue
            body = (resp.text or "").lower()
            if any(sig in body for sig in _SIGNATURES):
                findings.append(Finding(
                    id=f"DIRLIST-{idx:03d}",
                    title=f"Directory listing enabled: {path}",
                    severity=Severity.MEDIUM,
                    owasp="A05:2021 - Security Misconfiguration", cwe="CWE-548",
                    cvss=5.3, location=target.url(path),
                    description=f"The directory {path} returns an auto-generated "
                                "file index.",
                    evidence=body[:160].replace("\n", " "),
                    impact="Attackers can browse and download files not meant to "
                           "be listed (backups, source, uploads).",
                    remediation="Disable auto-indexing (e.g. 'Options -Indexes' "
                                "on Apache; 'autoindex off' on nginx).",
                    references=["https://cwe.mitre.org/data/definitions/548.html"]))
        return findings

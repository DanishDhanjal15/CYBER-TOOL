"""Cloud storage bucket exposure (S3 / GCS / Azure Blob).

Generates candidate bucket names from the target domain and probes public
storage endpoints. A listable bucket is a classic high-impact data leak.
"""
from __future__ import annotations

import re

from webrecon.checks.base import Check
from webrecon.core.config import Config
from webrecon.core.crawler import CrawlData
from webrecon.core.http_client import HttpClient
from webrecon.core.target import Target
from webrecon.model.finding import Finding
from webrecon.model.severity import Severity

_PREFIXES = ["", "backup-", "assets-", "static-", "dev-", "prod-", "media-"]
_SUFFIXES = ["", "-backup", "-assets", "-static", "-dev", "-prod", "-uploads",
             "-media", "-data", "-logs", "-public", "-private"]
_LISTING = ("<ListBucketResult", "<Contents>", '"items"', "EnumerationResults",
            "<Blobs>")


def _candidates(domain: str) -> list[str]:
    stem = re.sub(r"[^a-z0-9-]", "", domain.split(".")[0].lower())
    names = set()
    for p in _PREFIXES:
        for s in _SUFFIXES:
            names.add(f"{p}{stem}{s}")
    return sorted(n for n in names if 3 <= len(n) <= 63)[:40]


class CloudBucketCheck(Check):
    name = "buckets"
    description = "Public cloud storage bucket exposure (S3/GCS/Azure)."

    def run(self, target: Target, http: HttpClient, crawl: CrawlData,
            config: Config) -> list[Finding]:
        if target.is_ip:
            return []
        findings: list[Finding] = []
        for name in _candidates(target.host):
            for provider, url in (
                ("AWS S3", f"https://{name}.s3.amazonaws.com/"),
                ("Google Cloud Storage", f"https://storage.googleapis.com/{name}/"),
                ("Azure Blob", f"https://{name}.blob.core.windows.net/?comp=list"),
            ):
                resp = http.get(url, allow_redirects=False)
                if resp is None:
                    continue
                body = resp.text or ""
                if resp.status_code == 200 and any(m in body for m in _LISTING):
                    findings.append(_finding(provider, name, url, True, resp))
                elif resp.status_code in (200, 403) and any(
                        m in body for m in ("AccessDenied", "<Error>")):
                    findings.append(_finding(provider, name, url, False, resp))
        return findings


def _finding(provider, name, url, listable, resp) -> Finding:
    sev = Severity.HIGH if listable else Severity.LOW
    return Finding(
        id="BUCKET-001",
        title=f"{'Public listable' if listable else 'Existing private'} "
              f"{provider} bucket: {name}",
        severity=sev, owasp="A05:2021 - Security Misconfiguration", cwe="CWE-284",
        cvss=7.5 if listable else 2.0, location=url,
        confidence="CONFIRMED" if listable else "PROBABLE",
        description=f"A {provider} bucket named '{name}' "
                    + ("is publicly listable — its contents are exposed."
                       if listable else "exists but denies listing (asset only)."),
        evidence=f"HTTP {resp.status_code}; "
                 + ("object listing returned" if listable else "bucket exists"),
        impact=("Direct data exfiltration — backups, logs, PII, or secrets may be "
                "downloadable." if listable else
                "Confirms cloud footprint; try object reads / misconfig."),
        remediation="Make the bucket private; disable public listing; review "
                    "object ACLs and bucket policy.",
        poc=f"curl '{url}'",
        references=["https://cwe.mitre.org/data/definitions/284.html"])

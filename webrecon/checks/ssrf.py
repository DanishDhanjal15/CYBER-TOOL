"""Server-Side Request Forgery (SSRF) detection (conservative, low-FP).

Targets URL-style parameters. Because blind SSRF needs an external callback to
confirm, this check only reports when the server-fetched response reveals
strong internal-only signals (cloud metadata, internal service banners). That
keeps false positives low while still catching the high-impact cases.
"""
from __future__ import annotations

import time

from webrecon.checks.base import Check
from webrecon.checks._inject import enumerate_points, send, build_poc
from webrecon.core.config import Config
from webrecon.core.crawler import CrawlData
from webrecon.core.http_client import HttpClient
from webrecon.core.target import Target
from webrecon.model.finding import Finding
from webrecon.model.severity import Severity


_URL_PARAMS = ("url", "uri", "link", "src", "source", "dest", "target", "fetch",
               "load", "site", "host", "proxy", "callback", "webhook", "next",
               "data", "path", "image", "img", "feed", "open", "domain")

# (payload, signature that only appears if the server actually fetched it)
_PROBES = [
    ("http://169.254.169.254/latest/meta-data/",
     ("ami-id", "instance-id", "iam/", "meta-data", "hostname")),
    ("http://metadata.google.internal/computeMetadata/v1/",
     ("computeMetadata", "metadata-flavor", "project-id")),
    ("http://127.0.0.1:22/", ("ssh-", "openssh")),
    ("http://127.0.0.1:6379/", ("redis_version", "-ERR")),
]


class SsrfCheck(Check):
    name = "ssrf"
    description = "SSRF via URL params (confirms on internal/metadata signals)."

    def run(self, target: Target, http: HttpClient, crawl: CrawlData,
            config: Config) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        points = [p for p in enumerate_points(crawl)
                  if p.param.lower() in _URL_PARAMS]

        oast = getattr(config, "oast_server", None)

        for point in points:
            key = f"{point.url}|{point.param}"
            if key in seen:
                continue

            # Out-of-band confirmation: make the server fetch our OAST URL.
            if oast is not None:
                token = oast.new_token()
                send(http, point, oast.url_for(token))
                time.sleep(0.6)
                if oast.interactions(token):
                    seen.add(key)
                    findings.append(Finding(
                        id=f"SSRF-OOB-{len(findings)+1:03d}",
                        title=f"Blind SSRF confirmed (OOB) in '{point.param}'",
                        severity=Severity.CRITICAL,
                        owasp="A10:2021 - Server-Side Request Forgery",
                        cwe="CWE-918", cvss=9.1, location=point.url,
                        confidence="CONFIRMED",
                        description=f"The server fetched an attacker-controlled URL "
                                    f"supplied via '{point.param}' (verified via an "
                                    "out-of-band callback).",
                        evidence=f"OAST callback received for token {token}",
                        impact="Reach internal services, cloud metadata, and pivot "
                               "into the internal network.",
                        remediation="Allowlist outbound hosts/schemes; block "
                                    "internal ranges; do not fetch user-supplied "
                                    "URLs.",
                        poc=build_poc(point, oast.url_for(token)),
                        references=["https://cwe.mitre.org/data/definitions/"
                                    "918.html"]))
                    continue

            for payload, signatures in _PROBES:
                resp = send(http, point, payload)
                if resp is None:
                    continue
                body = (resp.text or "").lower()
                hit = next((s for s in signatures if s.lower() in body), None)
                if hit:
                    seen.add(key)
                    findings.append(Finding(
                        id=f"SSRF-{len(findings)+1:03d}",
                        title=f"Server-side request forgery in '{point.param}'",
                        severity=Severity.HIGH,
                        owasp="A10:2021 - Server-Side Request Forgery",
                        cwe="CWE-918", cvss=8.6, location=point.url,
                        confidence="PROBABLE",
                        description=f"The '{point.param}' parameter made the "
                                    "server fetch an internal URL; the response "
                                    "contained internal-only content.",
                        evidence=f"payload={payload!r}; internal signal={hit!r}",
                        impact="Read cloud metadata/credentials, reach internal "
                               "services, and pivot into the internal network.",
                        remediation="Allowlist outbound hosts/schemes; block "
                                    "link-local/private ranges; do not let user "
                                    "input control server-side fetch targets.",
                        poc=build_poc(point, payload),
                        references=["https://cwe.mitre.org/data/definitions/"
                                    "918.html"]))
                    break
        return findings

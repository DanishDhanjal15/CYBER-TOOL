"""IDOR / broken-object-level-access heuristic.

Numeric object-reference parameters (id, user_id, order, ...) are probed with
a neighbouring value. If a different valid-looking resource comes back with no
authorization barrier, it is flagged as a POTENTIAL IDOR for manual review.

This is a heuristic (no auth context), so findings are low-confidence by
design and must be verified by hand.
"""
from __future__ import annotations

from webrecon.checks.base import Check
from webrecon.checks._inject import enumerate_points, send, build_poc
from webrecon.core.config import Config
from webrecon.core.crawler import CrawlData
from webrecon.core.http_client import HttpClient
from webrecon.core.target import Target
from webrecon.model.finding import Finding
from webrecon.model.severity import Severity


_ID_PARAMS = ("id", "user", "user_id", "userid", "uid", "account", "account_id",
              "order", "order_id", "invoice", "doc", "document", "file", "fileid",
              "customer", "profile", "pid", "num", "no", "record")


def _similar(a: str, b: str) -> bool:
    """Two bodies look like the same template with different data."""
    if not a or not b:
        return False
    la, lb = len(a), len(b)
    if max(la, lb) == 0:
        return False
    ratio = min(la, lb) / max(la, lb)
    return ratio > 0.6


class IdorCheck(Check):
    name = "idor"
    description = "IDOR heuristic on numeric object-reference parameters."

    def run(self, target: Target, http: HttpClient, crawl: CrawlData,
            config: Config) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for point in enumerate_points(crawl):
            name = point.param.lower()
            if name not in _ID_PARAMS:
                continue
            original = point.base_params.get(point.param, "")
            if not str(original).isdigit():
                continue
            key = f"{point.url}|{point.param}"
            if key in seen:
                continue

            base_resp = send(http, point, str(original))
            if base_resp is None or base_resp.status_code != 200:
                continue
            neighbour = str(int(original) + 1)
            alt_resp = send(http, point, neighbour)
            if alt_resp is None or alt_resp.status_code != 200:
                continue

            base_body = base_resp.text or ""
            alt_body = alt_resp.text or ""
            # Different content, same structure, both reachable without auth.
            if base_body != alt_body and _similar(base_body, alt_body):
                seen.add(key)
                findings.append(Finding(
                    id=f"IDOR-{len(findings)+1:03d}",
                    title=f"Possible IDOR on '{point.param}'",
                    severity=Severity.MEDIUM,
                    owasp="A01:2021 - Broken Access Control", cwe="CWE-639",
                    cvss=6.5, location=point.url, confidence="POTENTIAL",
                    description=f"Changing '{point.param}' from {original} to "
                                f"{neighbour} returned a different valid resource "
                                "with no visible access-control barrier.",
                    evidence=f"id={original} and id={neighbour} both HTTP 200 "
                             "with distinct, similarly-structured bodies",
                    impact="If these objects belong to other users, an attacker "
                           "can enumerate and read/modify their data.",
                    remediation="Enforce per-object authorization server-side; "
                                "verify the current user owns the requested "
                                "object. Consider unguessable identifiers.",
                    poc=build_poc(point, neighbour),
                    references=["https://cwe.mitre.org/data/definitions/639.html"]))
        return findings

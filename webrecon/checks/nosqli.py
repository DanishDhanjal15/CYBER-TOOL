"""NoSQL injection detection (MongoDB-style operator injection)."""
from __future__ import annotations

from webrecon.checks.base import Check
from webrecon.checks._inject import enumerate_points, send, build_poc
from webrecon.core.config import Config
from webrecon.core.crawler import CrawlData
from webrecon.core.http_client import HttpClient
from webrecon.core.target import Target
from webrecon.data import load_lines
from webrecon.model.finding import Finding
from webrecon.model.severity import Severity


# Operator payloads (as param-value suffixes) that change query logic.
_PAYLOADS = ["[$ne]=1", "[$gt]=", "[$regex]=.*", "'||'1'=='1"]
_ERROR_SIGNS = ("mongoerror", "mongodb", "bson", "e11000", "cast to objectid",
                "$where", "unexpected token", "castError".lower())


class NoSqlInjectionCheck(Check):
    name = "nosqli"
    description = "NoSQL (MongoDB) operator injection."

    def run(self, target: Target, http: HttpClient, crawl: CrawlData,
            config: Config) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for point in enumerate_points(crawl):
            key = f"{point.url}|{point.param}"
            if key in seen:
                continue
            base = send(http, point, "1", baseline=True)
            base_body = (base.text or "") if base is not None else ""
            base_len = len(base_body)
            base_err = any(s in base_body.lower() for s in _ERROR_SIGNS)
            for payload in _PAYLOADS:
                # Inject operator by appending to the parameter name/value.
                resp = send(http, point, payload)
                if resp is None:
                    continue
                body = (resp.text or "")
                low = body.lower()
                err = any(s in low for s in _ERROR_SIGNS) and not base_err
                big_diff = base_len and abs(len(body) - base_len) / max(base_len, 1) > 0.5
                if err or (big_diff and resp.status_code == 200):
                    seen.add(key)
                    findings.append(Finding(
                        id=f"NOSQLI-{len(findings)+1:03d}",
                        title=f"Possible NoSQL injection in '{point.param}'",
                        severity=Severity.HIGH if err else Severity.MEDIUM,
                        owasp="A03:2021 - Injection", cwe="CWE-943",
                        cvss=8.2 if err else 5.4, location=point.url,
                        confidence="CONFIRMED" if err else "PROBABLE",
                        description=f"Operator injection into '{point.param}' altered "
                                    "the query" + (" and triggered a NoSQL error."
                                    if err else " response significantly."),
                        evidence=f"payload={payload!r}"
                                 + ("; NoSQL error surfaced" if err else
                                    f"; response size changed {base_len}->{len(body)}"),
                        impact="Authentication bypass or data extraction from a "
                               "NoSQL datastore.",
                        remediation="Validate/cast input types; reject query "
                                    "operators in user input; use parameterised "
                                    "queries.",
                        poc=build_poc(point, payload),
                        references=["https://cwe.mitre.org/data/definitions/943.html"]))
                    break
        return findings

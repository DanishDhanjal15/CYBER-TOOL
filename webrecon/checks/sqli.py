"""SQL injection detection: error-based and (aggressive) time-based."""
from __future__ import annotations

import time

from webrecon.checks.base import Check
from webrecon.checks._inject import enumerate_points, send, build_poc
from webrecon.core.config import Config
from webrecon.core.crawler import CrawlData
from webrecon.core.http_client import HttpClient
from webrecon.core.target import Target
from webrecon.data import load_lines
from webrecon.model.finding import Finding
from webrecon.model.severity import Severity


# Time-based payloads are only used in --aggressive mode (they add latency).
_TIME_PAYLOADS = [
    "1' AND SLEEP(5)-- -",
    "1) AND SLEEP(5)-- -",
    "1 AND SLEEP(5)",
    "1'; WAITFOR DELAY '0:0:5'-- -",
]
_DELAY_THRESHOLD = 4.0


class SqlInjectionCheck(Check):
    name = "sqli"
    description = "SQL injection (error-based; time-based in aggressive mode)."

    def run(self, target: Target, http: HttpClient, crawl: CrawlData,
            config: Config) -> list[Finding]:
        findings: list[Finding] = []
        error_signatures = load_lines("signatures/sql_errors.txt")
        payloads = list(load_lines("payloads/sqli.txt"))
        seen: set[str] = set()

        for point in enumerate_points(crawl):
            key = f"{point.url}|{point.param}"
            if key in seen:
                continue

            # Baseline body to compare against (avoid flagging pre-existing errors).
            base = send(http, point, "", baseline=True)
            base_body = (base.text or "").lower() if base is not None else ""
            base_has_err = any(sig in base_body for sig in error_signatures)

            found = False
            for payload in payloads:
                resp = send(http, point, payload)
                if resp is None:
                    continue
                body = (resp.text or "").lower()
                hit = next((s for s in error_signatures
                            if s in body and (base_has_err is False or s not in base_body)),
                           None)
                if hit:
                    seen.add(key)
                    findings.append(_error_finding(point, payload, hit))
                    found = True
                    break

            if found or not config.aggressive:
                continue

            # Time-based (aggressive only).
            for payload in _TIME_PAYLOADS:
                start = time.monotonic()
                resp = send(http, point, payload)
                elapsed = time.monotonic() - start
                if resp is not None and elapsed >= _DELAY_THRESHOLD:
                    # Confirm with a no-delay baseline timing.
                    t0 = time.monotonic()
                    send(http, point, "1", baseline=True)
                    base_elapsed = time.monotonic() - t0
                    if elapsed - base_elapsed >= _DELAY_THRESHOLD - 1:
                        seen.add(key)
                        findings.append(_time_finding(point, payload, elapsed))
                        break
        return findings


def _error_finding(point, payload, marker) -> Finding:
    return Finding(
        id="SQLI-001", title=f"SQL injection (error-based) in '{point.param}'",
        severity=Severity.CRITICAL, owasp="A03:2021 - Injection", cwe="CWE-89",
        cvss=9.8, location=point.url,
        description=f"Injecting into '{point.param}' produced a database error, "
                    "indicating unsanitised input reaches an SQL query.",
        evidence=f"payload={payload!r}; db-error marker={marker!r}",
        impact="Full read/modify access to the database; often leads to full "
               "system compromise.",
        remediation="Use parameterised queries / prepared statements; never "
                    "concatenate user input into SQL.",
        poc=build_poc(point, payload),
        references=["https://cwe.mitre.org/data/definitions/89.html"])


def _time_finding(point, payload, elapsed) -> Finding:
    return Finding(
        id="SQLI-002", title=f"SQL injection (time-based blind) in '{point.param}'",
        severity=Severity.CRITICAL, owasp="A03:2021 - Injection", cwe="CWE-89",
        cvss=9.8, location=point.url,
        description=f"A time-delay payload in '{point.param}' delayed the "
                    f"response by ~{elapsed:.1f}s, indicating blind SQLi.",
        evidence=f"payload={payload!r}; response_time={elapsed:.1f}s",
        impact="Blind extraction of database contents; potential full compromise.",
        remediation="Use parameterised queries / prepared statements.",
        poc=build_poc(point, payload),
        references=["https://cwe.mitre.org/data/definitions/89.html"])

"""Server-Side Template Injection (SSTI) detection.

Injects arithmetic template expressions and looks for the *evaluated* result
(49) in the response, without it being present in the raw payload — so a mere
reflection of the payload does not cause a false positive.
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


# Each payload evaluates to 49 in some template engine; none contains "49".
_PAYLOADS = [
    "${7*7}",        # JSP EL / Spring
    "{{7*7}}",       # Jinja2 / Twig / Nunjucks
    "#{7*7}",        # Ruby / Thymeleaf
    "<%= 7*7 %>",    # ERB
    "{7*7}",         # generic
    "${{7*7}}",
]
_EVAL = "49"


class SstiCheck(Check):
    name = "ssti"
    description = "Server-side template injection (evaluates 7*7 -> 49)."

    def run(self, target: Target, http: HttpClient, crawl: CrawlData,
            config: Config) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for point in enumerate_points(crawl):
            key = f"{point.url}|{point.param}"
            if key in seen:
                continue
            # Baseline must not already contain the evaluated result.
            base = send(http, point, "wrssti", baseline=True)
            base_body = (base.text or "") if base is not None else ""

            for payload in _PAYLOADS:
                if _EVAL in payload:      # safety: never use a payload with "49"
                    continue
                resp = send(http, point, payload)
                if resp is None:
                    continue
                body = resp.text or ""
                # Evaluated result present now, but not in baseline nor raw payload.
                if _EVAL in body and _EVAL not in base_body and _EVAL not in payload:
                    seen.add(key)
                    findings.append(Finding(
                        id=f"SSTI-{len(findings)+1:03d}",
                        title=f"Server-side template injection in '{point.param}'",
                        severity=Severity.CRITICAL,
                        owasp="A03:2021 - Injection", cwe="CWE-1336",
                        cvss=9.8, location=point.url, confidence="CONFIRMED",
                        description=f"Input in '{point.param}' is evaluated by a "
                                    "server-side template engine (7*7 rendered "
                                    "as 49).",
                        evidence=f"payload={payload!r} produced '49' in output",
                        impact="Template injection commonly escalates to remote "
                               "code execution on the server.",
                        remediation="Never render user input as a template; use a "
                                    "sandboxed engine and pass data as context "
                                    "variables only.",
                        poc=build_poc(point, payload),
                        references=["https://cwe.mitre.org/data/definitions/"
                                    "1336.html",
                                    "https://portswigger.net/web-security/"
                                    "server-side-template-injection"]))
                    break
        return findings

"""Basic OS command injection detection using a safe echo marker."""
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


# The payloads echo this marker; seeing it in output means command execution.
_MARKER = "CMDINJXOK"


class CommandInjectionCheck(Check):
    name = "cmdi"
    description = "OS command injection (safe echo-marker technique)."

    def run(self, target: Target, http: HttpClient, crawl: CrawlData,
            config: Config) -> list[Finding]:
        findings: list[Finding] = []
        payloads = list(load_lines("payloads/cmdi.txt"))
        seen: set[str] = set()
        oast = getattr(config, "oast_server", None)

        for point in enumerate_points(crawl):
            key = f"{point.url}|{point.param}"
            if key in seen:
                continue

            # Out-of-band (blind) confirmation via an OAST callback.
            if oast is not None:
                token = oast.new_token()
                host = oast.host_for(token)
                for oob in (f";curl http://{host}", f"|curl http://{host}",
                            f"$(curl http://{host})", f"`curl http://{host}`",
                            f";wget -q http://{host}"):
                    send(http, point, oob)
                time.sleep(0.8)
                if oast.interactions(token):
                    seen.add(key)
                    findings.append(Finding(
                        id=f"CMDI-OOB-{len(findings)+1:03d}",
                        title=f"Blind OS command injection (OOB) in '{point.param}'",
                        severity=Severity.CRITICAL, owasp="A03:2021 - Injection",
                        cwe="CWE-78", cvss=9.8, location=point.url,
                        confidence="CONFIRMED",
                        description=f"An injected shell command in '{point.param}' "
                                    "reached out to our OAST server, confirming "
                                    "server-side command execution.",
                        evidence=f"OAST callback received for token {token}",
                        impact="Arbitrary command execution on the server — full "
                               "compromise.",
                        remediation="Never pass user input to a shell; use safe "
                                    "APIs and strict allowlists.",
                        poc=f"curl 'http://{host}' via injected command",
                        references=["https://cwe.mitre.org/data/definitions/"
                                    "78.html"]))
                    continue

            # Baseline: the marker must NOT already be present.
            base = send(http, point, "1", baseline=True)
            if base is not None and _MARKER in (base.text or ""):
                continue
            for payload in payloads:
                resp = send(http, point, payload)
                if resp is None:
                    continue
                if _MARKER in (resp.text or ""):
                    seen.add(key)
                    findings.append(Finding(
                        id=f"CMDI-{len(findings)+1:03d}",
                        title=f"OS command injection in '{point.param}'",
                        severity=Severity.CRITICAL,
                        owasp="A03:2021 - Injection", cwe="CWE-78",
                        cvss=9.8, location=point.url,
                        description=f"Input in '{point.param}' is passed to a "
                                    "system shell; an injected echo executed.",
                        evidence=f"payload={payload!r}; marker reflected in output",
                        impact="Arbitrary command execution on the server — full "
                               "compromise.",
                        remediation="Avoid shelling out with user input; use safe "
                                    "APIs and strict allowlists; never pass input "
                                    "to a shell.",
                        poc=build_poc(point, payload),
                        references=["https://cwe.mitre.org/data/definitions/78.html"]))
                    break
        return findings

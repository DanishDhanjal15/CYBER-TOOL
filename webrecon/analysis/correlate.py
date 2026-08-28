"""Correlate findings into attack-path chains (higher-signal meta-findings).

Individual findings are useful; chained together they tell the real story
(e.g. an exposed .env plus a live cloud key = a direct path to compromise).
Each rule emits one extra Finding that references the underlying issues.
"""
from __future__ import annotations

from webrecon.model.finding import Finding
from webrecon.model.severity import Severity


def _has(findings, *rule_prefixes) -> list[Finding]:
    out = []
    for f in findings:
        rk = f.rule_key().upper()
        if any(rk.startswith(p.upper()) for p in rule_prefixes):
            out.append(f)
    return out


def correlate(findings: list[Finding]) -> list[Finding]:
    chains: list[Finding] = []

    # Chain 1: config/source exposure + a live hard-coded secret.
    exposure = _has(findings, "FILE", "JS-MAP", "TPL-exposed", "SECRET")
    secrets = [f for f in findings if f.rule_key().startswith("SECRET")]
    files = [f for f in findings if f.rule_key().startswith(("FILE", "TPL-exposed"))]
    if secrets and files:
        locs = ", ".join(sorted({f.location for f in (secrets + files)})[:4])
        chains.append(Finding(
            id="CHAIN-CRED-001",
            title="Attack chain: exposed config/source + live credential",
            severity=Severity.CRITICAL,
            owasp="A05:2021 - Security Misconfiguration", cwe="CWE-200",
            cvss=9.4, location=locs, confidence="CONFIRMED",
            description="A configuration/source file is publicly exposed AND a "
                        "hard-coded credential was found. Together these give an "
                        "attacker a direct path from public web to cloud/API "
                        "compromise.",
            evidence=f"{len(files)} exposure finding(s) + {len(secrets)} secret(s)",
            impact="Chained: read exposed files -> harvest credentials -> access "
                   "cloud/database/API. Prioritise above the individual items.",
            remediation="Remove exposed files, rotate every leaked secret, and "
                        "move secrets to a server-side vault.",
            references=[]))

    # Chain 2: multiple RCE-class injection points.
    rce = _has(findings, "SQLI", "CMDI", "SSTI", "XXE")
    critical_rce = [f for f in rce if f.severity == Severity.CRITICAL]
    if len(critical_rce) >= 2:
        kinds = sorted({f.rule_key() for f in critical_rce})
        chains.append(Finding(
            id="CHAIN-RCE-001",
            title=f"Attack chain: multiple RCE-class injection points "
                  f"({len(critical_rce)})",
            severity=Severity.CRITICAL, owasp="A03:2021 - Injection",
            cwe="CWE-707", cvss=9.8,
            location=", ".join(sorted({f.location for f in critical_rce})[:4]),
            confidence="CONFIRMED",
            description="Several independent server-side injection points were "
                        "confirmed; any one likely leads to full server "
                        "compromise.",
            evidence=f"types: {', '.join(kinds)}",
            impact="Multiple paths to remote code execution / data theft — the "
                   "application core is exploitable.",
            remediation="Treat as an emergency: patch input handling across all "
                        "affected endpoints and review the whole codebase.",
            references=[]))

    # Chain 3: reflected XSS with no Content-Security-Policy.
    xss = _has(findings, "XSS", "DOMXSS")
    no_csp = [f for f in findings if "content-security-policy" in f.title.lower()]
    if xss and no_csp:
        chains.append(Finding(
            id="CHAIN-XSS-001",
            title="Attack chain: reflected XSS with no CSP",
            severity=Severity.HIGH, owasp="A03:2021 - Injection", cwe="CWE-79",
            cvss=7.4, location=xss[0].location, confidence="CONFIRMED",
            description="XSS is present and there is no Content-Security-Policy to "
                        "contain it, so injected scripts run unrestricted.",
            evidence=f"{len(xss)} XSS finding(s) + missing CSP",
            impact="Full client-side compromise (session/token theft) with no "
                   "mitigating control.",
            remediation="Fix the XSS sink AND add a strict CSP as defence in "
                        "depth.",
            references=[]))
    return chains

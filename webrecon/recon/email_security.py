"""Email security posture: SPF / DMARC / DKIM / DNSSEC (spoof feasibility).

Follows offensive-osint §16.14. Produces findings for missing or weak email
authentication, which lets attackers spoof the domain in phishing.
"""
from __future__ import annotations

try:
    import dns.resolver
    _HAS_DNS = True
except Exception:  # pragma: no cover
    _HAS_DNS = False

from webrecon.core.target import Target
from webrecon.model.finding import Finding
from webrecon.model.severity import Severity


def _txt(name: str) -> list[str]:
    if not _HAS_DNS:
        return []
    try:
        return [b"".join(r.strings).decode("utf-8", "replace")
                for r in dns.resolver.resolve(name, "TXT")]
    except Exception:
        return []


def gather(target: Target) -> tuple[dict, list[Finding]]:
    info: dict = {}
    findings: list[Finding] = []
    if target.is_ip or not _HAS_DNS:
        info["note"] = "email checks skipped (IP target or dnspython missing)"
        return info, findings

    domain = target.host
    # SPF
    spf = next((t for t in _txt(domain) if t.lower().startswith("v=spf1")), None)
    info["spf"] = spf
    if not spf:
        findings.append(_f("EMAIL-SPF-001", "No SPF record", Severity.MEDIUM,
                           "The domain has no SPF record; anyone can send mail "
                           "claiming to be from it.",
                           "Publish an SPF record ending in '-all'.", domain,
                           "no v=spf1 TXT record"))
    elif spf.strip().endswith(("?all",)) or "+all" in spf:
        findings.append(_f("EMAIL-SPF-002", "Permissive SPF policy (?all/+all)",
                           Severity.MEDIUM, "SPF neither soft- nor hard-fails "
                           "unknown senders, so spoofs are likely delivered.",
                           "End SPF with '-all' (hard fail).", domain, spf[:120]))

    # DMARC
    dmarc = next((t for t in _txt(f"_dmarc.{domain}")
                  if t.lower().startswith("v=dmarc1")), None)
    info["dmarc"] = dmarc
    if not dmarc:
        findings.append(_f("EMAIL-DMARC-001", "No DMARC record", Severity.MEDIUM,
                           "Without DMARC, receivers can't reliably reject spoofed "
                           "mail from this domain.",
                           "Publish a DMARC record and move to p=quarantine then "
                           "p=reject.", domain, "no _dmarc TXT record"))
    else:
        policy = ""
        for part in dmarc.split(";"):
            part = part.strip().lower()
            if part.startswith("p="):
                policy = part[2:]
        info["dmarc_policy"] = policy
        if policy == "none":
            findings.append(_f("EMAIL-DMARC-002", "DMARC policy is p=none",
                               Severity.LOW, "DMARC is monitor-only; spoofed mail "
                               "is still delivered.",
                               "Enforce with p=quarantine or p=reject.", domain,
                               dmarc[:120]))

    # DNSSEC (informational hardening)
    try:
        ans = dns.resolver.resolve(domain, "DNSKEY")
        info["dnssec"] = bool(ans)
    except Exception:
        info["dnssec"] = False
        findings.append(_f("EMAIL-DNSSEC-001", "DNSSEC not enabled", Severity.INFO,
                           "DNS responses are not cryptographically signed.",
                           "Enable DNSSEC at the registrar/DNS provider.", domain,
                           "no DNSKEY record"))
    return info, findings


def _f(fid, title, sev, desc, fix, loc, ev) -> Finding:
    return Finding(
        id=fid, title=title, severity=sev,
        owasp="A05:2021 - Security Misconfiguration", cwe="CWE-290",
        cvss=5.3 if sev == Severity.MEDIUM else 2.0, location=loc,
        confidence="CONFIRMED", description=desc, evidence=ev,
        impact="Enables email spoofing / phishing that appears to come from the "
               "domain.",
        remediation=fix,
        references=["https://cwe.mitre.org/data/definitions/290.html"])

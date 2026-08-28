"""DNS recon: A/AAAA/MX/NS/TXT/CAA records, reverse DNS, and zone-transfer test."""
from __future__ import annotations

import socket

try:
    import dns.resolver
    import dns.reversename
    import dns.query
    import dns.zone
    _HAS_DNSPYTHON = True
except Exception:  # pragma: no cover
    _HAS_DNSPYTHON = False

from webrecon.core.target import Target
from webrecon.model.finding import Finding
from webrecon.model.severity import Severity


_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]


def gather(target: Target) -> tuple[dict, list[Finding]]:
    info: dict = {"host": target.host, "ip_addresses": target.ip_addresses,
                  "records": {}, "reverse_dns": {}}
    findings: list[Finding] = []

    if target.is_ip:
        info["records"] = {"note": "target is an IP; skipping name records"}
    elif _HAS_DNSPYTHON:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5.0
        for rtype in _RECORD_TYPES:
            try:
                answers = resolver.resolve(target.host, rtype)
                info["records"][rtype] = [r.to_text() for r in answers]
            except Exception:
                continue
        # CAA absent -> weak cert-issuance control (informational).
        if "CAA" not in info["records"]:
            findings.append(Finding(
                id="DNS-CAA-001", title="No CAA record (any CA may issue certs)",
                severity=Severity.INFO, owasp="A05:2021 - Security Misconfiguration",
                cwe="CWE-295", cvss=0.0, location=target.host, confidence="CONFIRMED",
                description="No DNS CAA record restricts which certificate "
                            "authorities may issue certificates for this domain.",
                evidence="no CAA record found",
                impact="A mis-issued certificate from any CA would be trusted.",
                remediation="Publish a CAA record naming your approved CA(s).",
                references=["https://cwe.mitre.org/data/definitions/295.html"]))
        # Zone transfer (AXFR) — a full zone dump is a serious leak.
        findings.extend(_zone_transfer(target.host, info["records"].get("NS", [])))
    else:
        info["records"] = {"note": "dnspython not installed; limited DNS info"}

    for ip in target.ip_addresses:
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            info["reverse_dns"][ip] = host
        except Exception:
            info["reverse_dns"][ip] = None
    return info, findings


def _zone_transfer(domain: str, ns_records: list) -> list[Finding]:
    findings: list[Finding] = []
    for ns in ns_records:
        ns_host = ns.rstrip(".")
        try:
            xfr = dns.query.xfr(ns_host, domain, lifetime=6.0)
            zone = dns.zone.from_xfr(xfr)
            names = [str(n) for n in zone.nodes.keys()]
            if names:
                findings.append(Finding(
                    id="DNS-AXFR-001",
                    title=f"DNS zone transfer allowed on {ns_host}",
                    severity=Severity.HIGH,
                    owasp="A05:2021 - Security Misconfiguration", cwe="CWE-200",
                    cvss=7.5, location=ns_host, confidence="CONFIRMED",
                    description=f"The nameserver {ns_host} allows AXFR zone "
                                f"transfer, dumping the entire DNS zone "
                                f"({len(names)} records).",
                    evidence=f"AXFR returned {len(names)} records: "
                             + ", ".join(names[:8]),
                    impact="Full internal DNS map disclosed — every host/subdomain "
                           "an attacker could target.",
                    remediation="Restrict zone transfers to authorized secondary "
                                "nameservers only.",
                    poc=f"dig @{ns_host} {domain} AXFR",
                    references=["https://cwe.mitre.org/data/definitions/200.html"]))
                break
        except Exception:
            continue
    return findings

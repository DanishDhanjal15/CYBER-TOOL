"""TLS/SSL inspection: certificate details, expiry, and protocol version.

Returns (info, findings). Findings flag expired/self-signed certs, near
expiry, and negotiation of legacy TLS versions.
"""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from webrecon.core.target import Target
from webrecon.model.finding import Finding
from webrecon.model.severity import Severity


_LEGACY_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}


def _parse_cert_time(value: str) -> datetime | None:
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc)
    except Exception:
        return None


def gather(target: Target) -> tuple[dict, list[Finding]]:
    findings: list[Finding] = []
    if target.scheme != "https" and target.port not in (443, 8443):
        return {"note": "target is not HTTPS; TLS checks skipped"}, findings

    host = target.host
    port = target.port if target.port not in (80,) else 443
    info: dict = {"host": host, "port": port}

    # 1) Verified handshake — detects self-signed / expired / hostname mismatch.
    verify_ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=6) as raw:
            with verify_ctx.wrap_socket(raw, server_hostname=host) as tls:
                info["protocol"] = tls.version()
                cert = tls.getpeercert()
                info["verified"] = True
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                info["subject"] = subject.get("commonName", "")
                info["issuer"] = issuer.get("commonName", "")
                info["not_after"] = cert.get("notAfter", "")
                exp = _parse_cert_time(cert.get("notAfter", ""))
                if exp:
                    days = (exp - datetime.now(timezone.utc)).days
                    info["days_to_expiry"] = days
                    if days < 0:
                        findings.append(_cert_expired(host, exp))
                    elif days < 21:
                        findings.append(_cert_expiring(host, days))
    except ssl.SSLCertVerificationError as exc:
        info["verified"] = False
        info["verify_error"] = str(exc)
        findings.append(_cert_invalid(host, str(exc)))
    except Exception as exc:
        info["error"] = str(exc)
        return info, findings

    # 2) Probe for legacy protocol support (best-effort).
    negotiated = info.get("protocol", "")
    if negotiated in _LEGACY_PROTOCOLS:
        findings.append(_legacy_tls(host, negotiated))

    # 3) Explicitly test whether deprecated TLS versions are still accepted.
    weak = _weak_versions(host, port)
    if weak:
        info["weak_protocols"] = weak
        findings.append(Finding(
            id="TLS-005", title=f"Deprecated TLS version(s) supported: "
                                f"{', '.join(weak)}",
            severity=Severity.MEDIUM, owasp="A02:2021 - Cryptographic Failures",
            cwe="CWE-327", cvss=5.0, location=host, confidence="CONFIRMED",
            description="The server still negotiates deprecated TLS versions.",
            evidence=f"accepted: {', '.join(weak)}",
            impact="Weak protocols are vulnerable to downgrade and known crypto "
                   "attacks (BEAST/POODLE); PCI-DSS forbids TLS 1.0.",
            remediation="Disable TLS 1.0 and 1.1; require TLS 1.2+ (prefer 1.3).",
            references=["https://cwe.mitre.org/data/definitions/327.html"]))

    return info, findings


def _weak_versions(host: str, port: int) -> list[str]:
    """Return the list of deprecated TLS versions the server accepts."""
    supported: list[str] = []
    versions = []
    for label, attr in (("TLSv1.0", "TLSv1"), ("TLSv1.1", "TLSv1_1")):
        v = getattr(ssl.TLSVersion, attr, None)
        if v is not None:
            versions.append((label, v))
    for label, ver in versions:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ver
            ctx.maximum_version = ver
            with socket.create_connection((host, port), timeout=5) as raw:
                with ctx.wrap_socket(raw, server_hostname=host):
                    supported.append(label)
        except Exception:
            continue
    return supported


def _cert_invalid(host: str, detail: str) -> Finding:
    return Finding(
        id="TLS-001", title="Invalid / untrusted TLS certificate",
        severity=Severity.MEDIUM, owasp="A02:2021 - Cryptographic Failures",
        cwe="CWE-295", cvss=5.3, location=host,
        description="The server's certificate failed standard validation "
                    "(self-signed, wrong hostname, or untrusted CA).",
        evidence=detail,
        impact="Users cannot distinguish the real site from a "
               "man-in-the-middle; encrypted traffic may be interceptable.",
        remediation="Install a certificate from a trusted CA (e.g. Let's "
                    "Encrypt) matching the hostname.",
        references=["https://cwe.mitre.org/data/definitions/295.html"],
    )


def _cert_expired(host: str, exp) -> Finding:
    return Finding(
        id="TLS-002", title="Expired TLS certificate",
        severity=Severity.HIGH, owasp="A02:2021 - Cryptographic Failures",
        cwe="CWE-298", cvss=7.4, location=host,
        description=f"The TLS certificate expired on {exp:%Y-%m-%d}.",
        evidence=f"notAfter={exp:%Y-%m-%d}",
        impact="Browsers show hard security warnings; traffic trust is broken.",
        remediation="Renew the certificate and automate renewal.",
        references=["https://cwe.mitre.org/data/definitions/298.html"],
    )


def _cert_expiring(host: str, days: int) -> Finding:
    return Finding(
        id="TLS-003", title="TLS certificate expiring soon",
        severity=Severity.LOW, owasp="A02:2021 - Cryptographic Failures",
        cwe="CWE-298", cvss=2.0, location=host,
        description=f"The TLS certificate expires in {days} day(s).",
        evidence=f"days_to_expiry={days}",
        impact="Imminent outage / trust warnings if not renewed.",
        remediation="Renew now and enable automated renewal.",
        references=[],
    )


def _legacy_tls(host: str, proto: str) -> Finding:
    return Finding(
        id="TLS-004", title=f"Legacy TLS protocol negotiated ({proto})",
        severity=Severity.MEDIUM, owasp="A02:2021 - Cryptographic Failures",
        cwe="CWE-327", cvss=5.0, location=host,
        description=f"The server negotiated {proto}, which is deprecated.",
        evidence=f"protocol={proto}",
        impact="Weak protocols are vulnerable to known downgrade/crypto attacks.",
        remediation="Disable TLS 1.1 and below; require TLS 1.2+ (prefer 1.3).",
        references=["https://cwe.mitre.org/data/definitions/327.html"],
    )

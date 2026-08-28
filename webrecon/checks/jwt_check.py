"""Passive JWT analysis.

Finds JSON Web Tokens the application hands out (cookies / response bodies),
decodes the header and payload (without verifying the signature), and flags
insecure configurations: 'alg: none', missing expiry, and sensitive claims.
"""
from __future__ import annotations

import base64
import binascii
import json
import re

from webrecon.checks.base import Check
from webrecon.core.config import Config
from webrecon.core.crawler import CrawlData
from webrecon.core.http_client import HttpClient
from webrecon.core.target import Target
from webrecon.model.finding import Finding
from webrecon.model.severity import Severity


_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
_SENSITIVE = ("password", "secret", "ssn", "credit", "card", "api_key",
              "apikey", "private")


def _b64json(segment: str):
    pad = "=" * (-len(segment) % 4)
    try:
        raw = base64.urlsafe_b64decode(segment + pad)
        return json.loads(raw)
    except (binascii.Error, ValueError, json.JSONDecodeError):
        return None


class JwtCheck(Check):
    name = "jwt"
    description = "Insecure JWT configuration (alg=none, no expiry, leaks)."

    def run(self, target: Target, http: HttpClient, crawl: CrawlData,
            config: Config) -> list[Finding]:
        resp = http.get(target.url("/"), allow_redirects=True)
        if resp is None:
            return []
        haystack = (resp.text or "") + " " + str(dict(resp.headers))
        tokens = set(_JWT_RE.findall(haystack))
        findings: list[Finding] = []

        for idx, token in enumerate(tokens, start=1):
            parts = token.split(".")
            header = _b64json(parts[0])
            payload = _b64json(parts[1]) if len(parts) > 1 else None
            if header is None:
                continue
            alg = str(header.get("alg", "")).lower()
            preview = token[:24] + "..."

            if alg == "none":
                findings.append(Finding(
                    id=f"JWT-{idx:03d}A",
                    title="JWT accepts 'alg: none' (unsigned token)",
                    severity=Severity.HIGH,
                    owasp="A02:2021 - Cryptographic Failures", cwe="CWE-347",
                    cvss=8.1, location=target.url("/"), confidence="CONFIRMED",
                    description="A JWT uses the 'none' algorithm, meaning it is "
                                "unsigned and can be forged.",
                    evidence=f"token={preview}; header alg=none",
                    impact="An attacker can forge arbitrary tokens (e.g. become "
                           "any user / admin).",
                    remediation="Reject 'none'; pin a strong algorithm (e.g. "
                                "RS256) and verify signatures server-side.",
                    poc=f"Decode/modify: {preview}",
                    references=["https://cwe.mitre.org/data/definitions/347.html"]))

            if payload is not None:
                if "exp" not in payload:
                    findings.append(Finding(
                        id=f"JWT-{idx:03d}B",
                        title="JWT has no expiry ('exp') claim",
                        severity=Severity.LOW,
                        owasp="A02:2021 - Cryptographic Failures", cwe="CWE-613",
                        cvss=3.7, location=target.url("/"), confidence="CONFIRMED",
                        description="A JWT lacks an 'exp' claim and never expires.",
                        evidence=f"token={preview}; claims={list(payload)[:8]}",
                        impact="A stolen token remains valid indefinitely.",
                        remediation="Add short-lived 'exp' and rotate/refresh "
                                    "tokens.",
                        references=["https://cwe.mitre.org/data/definitions/"
                                    "613.html"]))
                leaked = [k for k in payload
                          if any(s in k.lower() for s in _SENSITIVE)]
                if leaked:
                    findings.append(Finding(
                        id=f"JWT-{idx:03d}C",
                        title="JWT payload contains sensitive claim(s)",
                        severity=Severity.MEDIUM,
                        owasp="A02:2021 - Cryptographic Failures", cwe="CWE-312",
                        cvss=5.3, location=target.url("/"), confidence="CONFIRMED",
                        description="JWT payloads are only base64-encoded (not "
                                    "encrypted); sensitive fields are readable.",
                        evidence=f"sensitive claim(s): {', '.join(leaked)}",
                        impact="Anyone who sees the token can read the sensitive "
                               "values it carries.",
                        remediation="Never put secrets in a JWT payload; store "
                                    "server-side and reference by id.",
                        references=["https://cwe.mitre.org/data/definitions/"
                                    "312.html"]))
        return findings

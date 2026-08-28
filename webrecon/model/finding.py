"""The Finding data model — every detection is normalised into this shape."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse

from .severity import Severity


@dataclass
class Finding:
    id: str                      # stable id, e.g. "SEC-HEADERS-001"
    title: str                   # short human title
    severity: Severity           # CRITICAL / HIGH / MEDIUM / LOW / INFO
    owasp: str = ""              # e.g. "A05:2021 - Security Misconfiguration"
    cwe: str = ""               # e.g. "CWE-79"
    cvss: float = 0.0            # approximate 0.0-10.0
    location: str = ""          # affected URL / parameter / port
    description: str = ""        # what the issue is (plain language)
    evidence: str = ""          # proof: request/response snippet
    impact: str = ""            # what an attacker could do
    remediation: str = ""        # how to fix it
    references: list[str] = field(default_factory=list)
    # Validation-first fields (inspired by dynamic-exploitation scanners):
    confidence: str = "CONFIRMED"   # CONFIRMED / PROBABLE / POTENTIAL
    poc: str = ""                   # copy-paste reproduction (e.g. a curl cmd)
    # Raw HTTP evidence (ZAP-style request/response for this finding):
    request_raw: str = ""
    response_raw: str = ""

    def rule_key(self) -> str:
        """The check/rule this finding came from (id without its numeric index)."""
        return re.sub(r"-\d+[A-Za-z]?$", "", self.id) or self.id

    def fingerprint(self) -> str:
        """A stable id for the *same logical issue* across scans.

        Built from the rule, the host+path (query values dropped), and the
        title (which carries the affected parameter). Lets us dedupe within a
        scan and diff New/Fixed across scans.
        """
        parsed = urlparse(self.location or "")
        loc = f"{parsed.netloc}{parsed.path}" if parsed.netloc else \
            (self.location or "")
        basis = f"{self.rule_key()}|{loc}|{self.title}"
        return hashlib.sha1(basis.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["fingerprint"] = self.fingerprint()
        return d

    def __str__(self) -> str:
        return f"[{self.severity}] {self.title} @ {self.location or 'n/a'}"


@dataclass
class ScanResult:
    """Everything produced by a single scan run."""
    target: str
    started_at: str
    finished_at: str = ""
    duration_seconds: float = 0.0
    findings: list[Finding] = field(default_factory=list)
    recon: dict = field(default_factory=dict)   # raw recon info (dns, ports, tls...)
    stats: dict = field(default_factory=dict)   # crawled counts, requests sent...
    transactions: list = field(default_factory=list)  # full HTTP traffic log (HAR)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def extend(self, findings) -> None:
        self.findings.extend(findings)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.severity.rank, reverse=True)

    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": round(self.duration_seconds, 2),
            "counts": self.counts(),
            "recon": self.recon,
            "stats": self.stats,
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }

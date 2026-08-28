"""Deduplicate findings by fingerprint (DefectDojo-style intelligent merge).

Two detections of the same logical issue (same rule + location + parameter)
collapse into one, keeping the highest-severity instance and noting how many
times it was seen.
"""
from __future__ import annotations

from webrecon.model.finding import Finding


def dedup(findings: list[Finding]) -> list[Finding]:
    best: dict[str, Finding] = {}
    counts: dict[str, int] = {}
    for f in findings:
        fp = f.fingerprint()
        counts[fp] = counts.get(fp, 0) + 1
        if fp not in best or f.severity.rank > best[fp].severity.rank:
            best[fp] = f
    result: list[Finding] = []
    for fp, f in best.items():
        if counts[fp] > 1 and "seen" not in f.evidence:
            f.evidence = (f.evidence + f"  (deduped: seen {counts[fp]}x)").strip()
        result.append(f)
    return result

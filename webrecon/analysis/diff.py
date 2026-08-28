"""Diff two scans of the same target by finding fingerprint.

Classifies each finding as NEW (appeared since the baseline), FIXED (was in
the baseline but gone now), or UNCHANGED. Powers 'what changed since last time'.
"""
from __future__ import annotations


def diff_scans(store, current_id: int, baseline_id: int) -> dict:
    cur = store.fingerprints(current_id)
    base = store.fingerprints(baseline_id)
    cur_fps = set(cur)
    base_fps = set(base)

    new = [cur[fp] for fp in cur_fps - base_fps]
    fixed = [base[fp] for fp in base_fps - cur_fps]
    unchanged = [cur[fp] for fp in cur_fps & base_fps]

    order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    new.sort(key=lambda f: order.get(f["severity"], 0), reverse=True)
    fixed.sort(key=lambda f: order.get(f["severity"], 0), reverse=True)
    return {
        "current_id": current_id,
        "baseline_id": baseline_id,
        "new": new,
        "fixed": fixed,
        "unchanged": unchanged,
        "summary": {"new": len(new), "fixed": len(fixed),
                    "unchanged": len(unchanged)},
    }

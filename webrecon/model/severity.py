"""Severity levels, ordering, colors, and risk-score weighting."""
from __future__ import annotations

from enum import Enum


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """Higher = more severe. Used for sorting."""
        return _RANK[self]

    @property
    def color(self) -> str:
        """A `rich`-compatible color name."""
        return _COLOR[self]

    @property
    def weight(self) -> int:
        """Contribution of a single finding toward the overall risk score."""
        return _WEIGHT[self]

    def __str__(self) -> str:  # nicer output in f-strings / templates
        return self.value


_RANK = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}

_COLOR = {
    Severity.CRITICAL: "bright_red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "blue",
}

_WEIGHT = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0,
}


def risk_score(findings) -> int:
    """Aggregate findings into a 0-100 overall risk score.

    Uses a saturating sum of per-severity weights so a handful of critical
    issues quickly pushes the score toward 100 without a single finding
    maxing it out.
    """
    total = sum(f.severity.weight for f in findings)
    # Saturate: 100 * (1 - e^-total/60) approximated with a simple cap.
    if total >= 100:
        return 100
    return int(total)


def risk_band(score: int) -> str:
    if score >= 70:
        return "CRITICAL"
    if score >= 40:
        return "HIGH"
    if score >= 15:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "CLEAN"

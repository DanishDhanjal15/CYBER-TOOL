"""Early-failure prediction for data-centre / HPC fleets.

Ingests component telemetry (CSV or JSON) — SMART disk attributes, ECC memory
error counts, temperatures, fan/power — and applies well-established
statistical predictors to estimate which components are likely to fail soon
and, where a metric is trending toward a critical threshold, an approximate
time-to-failure.

This is a heuristic/statistical model (no training required): it combines
threshold rules on known-predictive attributes (Backblaze SMART 5/187/197/198,
rising ECC correctable rates, sustained thermals) with linear-trend
extrapolation and z-score anomaly detection. It is designed to run offline on
exported telemetry.
"""
from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from webrecon.model.finding import Finding, ScanResult
from webrecon.model.severity import Severity


# canonical -> (aliases, warn, crit, ttf_threshold, weight, label)
# higher value is always worse for these signals.
SIGNALS = {
    "smart_reallocated": (("reallocated", "smart_5", "attr5"), 1, 40, 100, 25,
                          "Reallocated sectors (SMART 5)"),
    "smart_pending":     (("pending", "current_pending", "smart_197", "attr197"),
                          1, 10, 50, 30, "Pending sectors (SMART 197)"),
    "smart_uncorrectable": (("uncorrectable", "offline_uncorrect", "smart_198",
                             "attr198"), 1, 5, 30, 30,
                            "Uncorrectable sectors (SMART 198)"),
    "smart_crc":         (("crc", "smart_199", "udma_crc"), 1, 50, 200, 10,
                          "UDMA CRC errors (SMART 199)"),
    "smart_reported_uncorrect": (("reported_uncorrect", "smart_187", "attr187"),
                                 1, 10, 40, 25, "Reported uncorrectable (SMART 187)"),
    "media_wearout":     (("wearout", "percent_used", "wear_level", "ssd_life",
                           "life_used"), 85, 95, 100, 20, "SSD wear (% used)"),
    "ecc_correctable":   (("correctable", "ce_count", "ecc_ce", "corrected_errors"),
                          1000, 100000, 1_000_000, 15,
                          "ECC correctable errors"),
    "ecc_uncorrectable": (("ue_count", "ecc_ue", "uncorrected_errors"), 1, 1, 1,
                          40, "ECC uncorrectable errors"),
    "temperature":       (("temp", "temperature", "celsius"), 65, 80, 90, 15,
                          "Temperature (°C)"),
    "fan_rpm":           (("fan", "rpm"), 0, 0, 0, 0, "Fan RPM"),  # info only
    "power_w":           (("power", "watt"), 0, 0, 0, 0, "Power (W)"),
}

_ID_ALIASES = ("component", "node", "host", "hostname", "device", "serial",
               "serial_number", "disk", "id", "name", "gpu", "server")
_TIME_ALIASES = ("timestamp", "time", "date", "datetime", "ts")


@dataclass
class Series:
    values: list[float] = field(default_factory=list)
    times: list[float] = field(default_factory=list)   # days since first sample


def _load_records(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix.lower() == ".json":
        data = json.loads(text)
        if isinstance(data, dict):
            data = data.get("records") or data.get("data") or [data]
        return [r for r in data if isinstance(r, dict)]
    rows = list(csv.DictReader(text.splitlines()))
    return rows


def _match_column(columns, aliases) -> str | None:
    for col in columns:
        cl = col.lower()
        if any(a in cl for a in aliases):
            return col
    return None


def _parse_time(v: str) -> float | None:
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d",
                "%Y/%m/%d %H:%M:%S", "%Y/%m/%d"):
        try:
            return datetime.strptime(str(v).strip()[:19], fmt).replace(
                tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    try:
        return float(v)  # epoch seconds
    except (ValueError, TypeError):
        return None


def _slope(xs: list[float], ys: list[float]) -> float:
    """Least-squares slope of ys over xs (per x-unit)."""
    n = len(xs)
    if n < 2:
        return 0.0
    mx = sum(xs) / n
    my = sum(ys) / n
    denom = sum((x - mx) ** 2 for x in xs)
    if denom == 0:
        return 0.0
    return sum((xs[i] - mx) * (ys[i] - my) for i in range(n)) / denom


def _zscore(ys: list[float]) -> float:
    n = len(ys)
    if n < 3:
        return 0.0
    mean = sum(ys) / n
    var = sum((y - mean) ** 2 for y in ys) / n
    if var == 0:
        return 0.0
    return (ys[-1] - mean) / (var ** 0.5)


def _to_float(v):
    try:
        return float(str(v).strip())
    except (ValueError, TypeError):
        return None


def analyze(path: str) -> ScanResult:
    p = Path(path)
    started = datetime.now(timezone.utc)
    result = ScanResult(target=f"predict://{p.name}", started_at=started.isoformat())

    records = _load_records(p)
    if not records:
        result.finished_at = datetime.now(timezone.utc).isoformat()
        return result
    columns = list(records[0].keys())

    id_col = _match_column(columns, _ID_ALIASES) or columns[0]
    time_col = _match_column(columns, _TIME_ALIASES)
    signal_cols = {}
    for canon, spec in SIGNALS.items():
        col = _match_column(columns, spec[0])
        if col:
            signal_cols[canon] = col

    # Group series per component per signal.
    comps: dict[str, dict[str, Series]] = {}
    for rec in records:
        cid = str(rec.get(id_col, "unknown"))
        t = _parse_time(rec[time_col]) if time_col and rec.get(time_col) else None
        for canon, col in signal_cols.items():
            val = _to_float(rec.get(col))
            if val is None:
                continue
            s = comps.setdefault(cid, {}).setdefault(canon, Series())
            s.values.append(val)
            s.times.append(t if t is not None else float(len(s.values)))

    # Normalise times to days-since-first per component.
    for sigs in comps.values():
        base = min((s.times[0] for s in sigs.values() if s.times), default=0.0)
        for s in sigs.values():
            if s.times and max(s.times) > 1e6:  # looks like epoch seconds
                s.times = [(t - base) / 86400.0 for t in s.times]

    for cid, sigs in comps.items():
        score = 0
        drivers: list[str] = []
        ttf_days: float | None = None
        for canon, s in sigs.items():
            aliases, warn, crit, ttf_th, weight, label = SIGNALS[canon]
            if weight == 0 or not s.values:
                continue
            cur = s.values[-1]
            contrib = 0
            if cur >= crit:
                contrib = weight
            elif cur >= warn:
                contrib = int(weight * 0.5)
            slope = _slope(s.times, s.values) if len(s.values) >= 2 else 0.0
            z = _zscore(s.values)
            if slope > 0 and z > 2:                 # worsening + anomalous
                contrib = max(contrib, int(weight * 0.6))
            if contrib:
                trend = f", rising {slope:.2f}/day" if slope > 0 else ""
                drivers.append(f"{label}: {cur:g}{trend}")
                score += contrib
                # Extrapolate a time-to-failure toward the critical threshold.
                if slope > 0 and cur < ttf_th:
                    days = (ttf_th - cur) / slope
                    if days > 0 and (ttf_days is None or days < ttf_days):
                        ttf_days = days
        if score <= 0:
            continue
        score = min(100, score)
        sev = (Severity.CRITICAL if score >= 70 else
               Severity.HIGH if score >= 45 else
               Severity.MEDIUM if score >= 20 else Severity.LOW)
        window = (f"~{ttf_days:.0f} day(s) to critical threshold at current trend"
                  if ttf_days is not None else
                  "already at/over threshold — inspect now")
        result.add(Finding(
            id=f"HW-RISK-{abs(hash(cid)) % 10000:04d}",
            title=f"Predicted early failure risk: {cid}",
            severity=sev, owasp="Reliability - Predictive Maintenance",
            cwe="", cvss=0.0, location=str(cid),
            confidence="PROBABLE" if ttf_days is not None else "POTENTIAL",
            description=f"Component '{cid}' shows failure-predictive telemetry. "
                        f"Risk score {score}/100.",
            evidence="; ".join(drivers[:6]),
            impact=f"Likely hardware failure — {window}. Unplanned failure can "
                   "cause data loss, job aborts, or node downtime.",
            remediation="Schedule proactive replacement / migration of workloads "
                        "off this component; back up data; open a maintenance "
                        "ticket. Re-check after the next telemetry interval.",
            poc=f"predicted_window={window}; drivers={len(drivers)}",
            references=["https://www.backblaze.com/blog/"
                        "what-smart-stats-indicate-hard-drive-failures/"]))

    finished = datetime.now(timezone.utc)
    result.finished_at = finished.isoformat()
    result.duration_seconds = (finished - started).total_seconds()
    result.stats = {"records": len(records), "components": len(comps),
                    "signals_detected": sorted(signal_cols.keys()),
                    "at_risk": len(result.findings)}
    return result

"""SQLite-backed scan history.

Every scan and its findings are persisted so results can be listed, compared
over time (diff mode), and later surfaced in a dashboard. Pure stdlib sqlite3.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from webrecon.model.finding import ScanResult
from webrecon.model.severity import risk_score

DEFAULT_DB = "webrecon.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    duration REAL,
    risk_score INTEGER,
    total_findings INTEGER,
    counts_json TEXT,
    stats_json TEXT,
    is_baseline INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    fingerprint TEXT,
    rule_key TEXT,
    finding_id TEXT,
    title TEXT,
    severity TEXT,
    owasp TEXT,
    cwe TEXT,
    cvss REAL,
    location TEXT,
    confidence TEXT,
    description TEXT,
    evidence TEXT,
    impact TEXT,
    remediation TEXT,
    poc TEXT,
    refs_json TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
"""


class Store:
    def __init__(self, path: str | Path = DEFAULT_DB):
        self.path = str(path)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    # -- writes -----------------------------------------------------------
    def save_scan(self, result: ScanResult) -> int:
        counts = result.counts()
        score = risk_score(result.findings)
        cur = self.conn.execute(
            "INSERT INTO scans (target, started_at, finished_at, duration, "
            "risk_score, total_findings, counts_json, stats_json) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (result.target, result.started_at, result.finished_at,
             result.duration_seconds, score, len(result.findings),
             json.dumps(counts), json.dumps(result.stats)))
        scan_id = cur.lastrowid
        for f in result.findings:
            self.conn.execute(
                "INSERT INTO findings (scan_id, fingerprint, rule_key, finding_id, "
                "title, severity, owasp, cwe, cvss, location, confidence, "
                "description, evidence, impact, remediation, poc, refs_json) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (scan_id, f.fingerprint(), f.rule_key(), f.id, f.title,
                 f.severity.value, f.owasp, f.cwe, f.cvss, f.location,
                 f.confidence, f.description, f.evidence, f.impact,
                 f.remediation, f.poc, json.dumps(f.references)))
        self.conn.commit()
        return scan_id

    def set_baseline(self, scan_id: int) -> None:
        row = self.conn.execute("SELECT target FROM scans WHERE id=?",
                                (scan_id,)).fetchone()
        if row:
            self.conn.execute("UPDATE scans SET is_baseline=0 WHERE target=?",
                              (row["target"],))
            self.conn.execute("UPDATE scans SET is_baseline=1 WHERE id=?",
                              (scan_id,))
            self.conn.commit()

    # -- reads ------------------------------------------------------------
    def list_scans(self, target: str | None = None, limit: int = 25) -> list[dict]:
        if target:
            rows = self.conn.execute(
                "SELECT * FROM scans WHERE target=? ORDER BY id DESC LIMIT ?",
                (target, limit)).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def get_findings(self, scan_id: int) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM findings WHERE scan_id=?", (scan_id,)).fetchall()
        return [dict(r) for r in rows]

    def previous_scan_id(self, target: str, before_id: int | None = None) -> int | None:
        if before_id is not None:
            row = self.conn.execute(
                "SELECT id FROM scans WHERE target=? AND id<? ORDER BY id DESC "
                "LIMIT 1", (target, before_id)).fetchone()
        else:
            row = self.conn.execute(
                "SELECT id FROM scans WHERE target=? ORDER BY id DESC LIMIT 1",
                (target,)).fetchone()
        return row["id"] if row else None

    def baseline_scan_id(self, target: str) -> int | None:
        row = self.conn.execute(
            "SELECT id FROM scans WHERE target=? AND is_baseline=1 "
            "ORDER BY id DESC LIMIT 1", (target,)).fetchone()
        return row["id"] if row else None

    def fingerprints(self, scan_id: int) -> dict[str, dict]:
        return {r["fingerprint"]: dict(r) for r in self.get_findings(scan_id)}

"""Tests for continuous-monitoring: interval parsing, alert formatting,
severity filtering, and file/console channels (no network)."""
import json
import tempfile
from pathlib import Path

import pytest

from webrecon.monitor.notify import Notifier, Alert
from webrecon.monitor.runner import parse_interval


def _find(sev, title="Issue"):
    return {"severity": sev, "title": title, "location": "http://x/a"}


# ---- interval parsing ---------------------------------------------------
def test_parse_interval():
    assert parse_interval("30s") == 30
    assert parse_interval("5m") == 300
    assert parse_interval("1h") == 3600
    assert parse_interval("1d") == 86400
    assert parse_interval("3600") == 3600
    with pytest.raises(ValueError):
        parse_interval("soon")


# ---- alert formatting ---------------------------------------------------
def test_alert_text_and_worst_severity():
    a = Alert("http://x", [_find("HIGH", "XSS"), _find("CRITICAL", "SQLi")])
    assert a.worst_severity() == "CRITICAL"
    txt = a.to_text()
    assert "http://x" in txt and "2 new" in txt and "XSS" in txt


# ---- severity filtering -------------------------------------------------
def test_min_severity_filters_low_findings():
    n = Notifier(min_severity="high")
    # only medium/low present -> nothing passes -> no channels fire
    alert = Alert("http://x", [_find("MEDIUM"), _find("LOW")])
    assert n.send(alert) == []
    # a high finding passes
    alert2 = Alert("http://x", [_find("HIGH"), _find("LOW")])
    class _C:
        def __init__(self): self.msgs = []
        def print(self, *a, **k): self.msgs.append(a)
    n2 = Notifier(min_severity="high", console=_C())
    assert "console" in n2.send(alert2)


# ---- log channel --------------------------------------------------------
def test_log_channel_writes_jsonl():
    with tempfile.TemporaryDirectory() as d:
        log = Path(d) / "alerts.jsonl"
        n = Notifier(log_file=str(log), min_severity="info")
        fired = n.send(Alert("http://x", [_find("HIGH", "XSS")], scan_id=7))
        assert "log" in fired
        line = json.loads(log.read_text(encoding="utf-8").strip())
        assert line["target"] == "http://x" and line["scan_id"] == 7
        assert line["new"][0]["title"] == "XSS"


def test_no_channels_configured_still_safe():
    # only console-less, no file/webhook/email -> nothing fires, no crash
    n = Notifier(min_severity="info")
    assert n.send(Alert("http://x", [_find("CRITICAL")])) == []

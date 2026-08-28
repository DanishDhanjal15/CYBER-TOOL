"""Tests for request/response capture, HAR export, and evidence attach."""
import json
import tempfile
from pathlib import Path

from webrecon.core.http_trace import render_request, render_response, attach_evidence
from webrecon.report import har_report
from webrecon.model.finding import Finding, ScanResult
from webrecon.model.severity import Severity
from webrecon.core.config import Config
from webrecon.core.http_client import HttpClient


_TXN = {
    "method": "POST", "url": "http://x.test/login?next=/a",
    "req_headers": {"User-Agent": "WebRecon", "Content-Type": "application/x-www-form-urlencoded"},
    "req_body": "user=admin&pass=1", "status": 302,
    "resp_headers": {"Location": "/dashboard", "Set-Cookie": "s=1"},
    "resp_body": "redirecting", "time_ms": 12.3,
}


def test_render_request():
    raw = render_request(_TXN)
    assert raw.startswith("POST /login?next=/a HTTP/1.1")
    assert "Host: x.test" in raw
    assert "user=admin&pass=1" in raw


def test_render_response():
    raw = render_response(_TXN)
    assert raw.startswith("HTTP/1.1 302")
    assert "Location: /dashboard" in raw and "redirecting" in raw


def test_attach_evidence_by_url_and_path():
    f1 = Finding(id="X-1", title="a", severity=Severity.LOW,
                 location="http://x.test/login?next=/a")
    f2 = Finding(id="Y-1", title="b", severity=Severity.LOW,
                 location="http://x.test/login")     # matches by path
    attach_evidence([f1, f2], [_TXN])
    assert "POST /login" in f1.request_raw
    assert "HTTP/1.1 302" in f2.response_raw


def test_har_export_valid():
    r = ScanResult(target="http://x.test", started_at="t")
    r.transactions = [_TXN]
    with tempfile.TemporaryDirectory() as d:
        p = har_report.write(r, Path(d) / "t.har")
        doc = json.loads(p.read_text(encoding="utf-8"))
    assert doc["log"]["version"] == "1.2"
    e = doc["log"]["entries"][0]
    assert e["request"]["method"] == "POST"
    assert e["response"]["status"] == 302
    assert e["request"]["queryString"][0]["name"] == "next"


def test_http_client_records_transactions():
    http = HttpClient(Config())
    class _R:
        status_code = 200
        headers = {"Content-Type": "text/html"}
        text = "ok"
    http._record("GET", "http://x.test/", {"headers": {"X-Test": "1"}}, _R(), 5.0)
    assert len(http.transactions) == 1
    t = http.transactions[0]
    assert t["url"] == "http://x.test/" and t["status"] == 200
    assert t["req_headers"].get("X-Test") == "1"
    assert http.last_transaction() is t

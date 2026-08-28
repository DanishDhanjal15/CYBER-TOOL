"""Tests for scan history, diff, dedup/correlation, and CVE enrichment."""
import tempfile
from pathlib import Path

from webrecon.model.finding import Finding, ScanResult
from webrecon.model.severity import Severity
from webrecon.analysis.dedup import dedup
from webrecon.analysis.correlate import correlate
from webrecon.analysis.diff import diff_scans
from webrecon.storage.db import Store
from webrecon.checks.cve_check import _lt, CveCheck
from webrecon.core.config import Config
from webrecon.core.crawler import CrawlData
from webrecon.core.target import parse_target


def _f(fid, title, sev=Severity.HIGH, loc="http://x/a"):
    return Finding(id=fid, title=title, severity=sev, location=loc)


# ---- fingerprint + dedup ------------------------------------------------
def test_fingerprint_stable_and_distinct():
    a = _f("XSS-001", "Reflected XSS in 'q'", loc="http://x/s?q=1")
    b = _f("XSS-005", "Reflected XSS in 'q'", loc="http://x/s?q=zzz")  # same issue
    c = _f("XSS-002", "Reflected XSS in 'id'", loc="http://x/s?q=1")   # diff param
    assert a.fingerprint() == b.fingerprint()   # query value ignored
    assert a.fingerprint() != c.fingerprint()


def test_dedup_collapses_duplicates():
    a = _f("XSS-001", "Reflected XSS in 'q'", loc="http://x/s?q=1")
    b = _f("XSS-009", "Reflected XSS in 'q'", loc="http://x/s?q=2")
    out = dedup([a, b, _f("HDR-1", "Missing CSP")])
    assert len(out) == 2


# ---- correlation --------------------------------------------------------
def test_correlate_credential_chain():
    findings = [_f("FILE-001", "Sensitive file exposed: /.env",
                   Severity.HIGH, "http://x/.env"),
                _f("SECRET-001", "Hard-coded secret exposed: AWS Access Key",
                   Severity.CRITICAL, "http://x/app.js")]
    chains = correlate(findings)
    assert any("chain" in c.title.lower() and c.severity == Severity.CRITICAL
               for c in chains)


# ---- storage + diff -----------------------------------------------------
def _result(target, findings):
    r = ScanResult(target=target, started_at="2026-01-01T00:00:00")
    r.extend(findings)
    return r


def test_store_save_list_and_diff():
    with tempfile.TemporaryDirectory() as d:
        store = Store(Path(d) / "t.db")
        s1 = store.save_scan(_result("http://x", [
            _f("HDR-1", "Missing CSP"), _f("XSS-001", "Reflected XSS in 'q'")]))
        s2 = store.save_scan(_result("http://x", [
            _f("HDR-1", "Missing CSP"),                       # unchanged
            _f("SQLI-001", "SQL injection in 'id'", Severity.CRITICAL)]))  # new
        assert len(store.list_scans("http://x")) == 2
        d2 = diff_scans(store, s2, s1)
        assert d2["summary"]["new"] == 1      # SQLi
        assert d2["summary"]["fixed"] == 1    # XSS gone
        assert d2["summary"]["unchanged"] == 1
        store.close()


# ---- CVE matching -------------------------------------------------------
def test_version_less_than():
    assert _lt("1.12.4", "3.5.0") is True
    assert _lt("3.6.0", "3.5.0") is False
    assert _lt("2.4.49", "2.4.50") is True


class _JsHttp:
    def get(self, url, **k):
        class R:
            status_code = 200
            headers = {"Server": "nginx/1.18.0"}
            text = "/*! jQuery JavaScript Library v1.12.4 */"
            url = "http://x/"
        return R()

    request = get
    post = get
    head = get


def test_cve_check_matches_jquery():
    t = parse_target("http://example.com")
    crawl = CrawlData()
    crawl.js_urls.append("http://example.com/app.js")
    findings = CveCheck().run(t, _JsHttp(), crawl, Config())
    ids = [f.id for f in findings]
    assert any("CVE-2020-11022" in i for i in ids)   # jQuery < 3.5.0
    assert any("CVE-2021-23017" in i for i in ids)   # nginx < 1.21.0

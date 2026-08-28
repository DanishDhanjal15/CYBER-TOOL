"""Tests for the Perimetry-inspired recon features (mocked network)."""
import json

from webrecon.recon import ct_logs, wayback
from webrecon.checks.cloud_buckets import _candidates, CloudBucketCheck
from webrecon.checks.csp_analyzer import CspAnalyzerCheck
from webrecon.checks.content_discovery import ContentDiscoveryCheck
from webrecon.checks.web_recon import WebReconCheck
from webrecon.checks.waf import WafCdnCheck
from webrecon.core.config import Config
from webrecon.core.crawler import CrawlData
from webrecon.core.target import parse_target


class FakeResp:
    def __init__(self, status=200, text="", headers=None, jsond=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}
        self._json = jsond
    def json(self):
        return self._json if self._json is not None else json.loads(self.text)


# ---- CT logs (crt.sh) ---------------------------------------------------
def test_ct_log_parsing(monkeypatch):
    payload = json.dumps([
        {"name_value": "www.example.com\napi.example.com"},
        {"name_value": "*.example.com"},
        {"name_value": "mail.other.com"},          # different domain, ignored
    ])
    monkeypatch.setattr(ct_logs.requests, "get",
                        lambda *a, **k: FakeResp(200, payload))
    subs = ct_logs.enumerate_subdomains("example.com")
    assert "www.example.com" in subs and "api.example.com" in subs
    assert "mail.other.com" not in subs


# ---- Wayback CDX --------------------------------------------------------
def test_wayback_parsing_prioritises_params(monkeypatch):
    rows = [["original"],
            ["https://example.com/page"],
            ["https://example.com/item?id=1"],
            ["https://evil.com/x"]]
    monkeypatch.setattr(wayback.requests, "get",
                        lambda *a, **k: FakeResp(200, jsond=rows))
    urls = wayback.discover_urls("example.com")
    assert "https://example.com/item?id=1" in urls
    assert all("evil.com" not in u for u in urls)          # scope enforced
    assert "?" in urls[0]                                   # param URL first


# ---- Cloud buckets ------------------------------------------------------
def test_bucket_candidates():
    names = _candidates("acme.com")
    assert "acme" in names and any(n.startswith("backup-") for n in names)
    assert all(3 <= len(n) <= 63 for n in names)


class _FakeHttp:
    def __init__(self, resp):
        self._r = resp
    def get(self, u, **k):
        return self._r
    request = get
    post = get


# ---- CSP analyzer -------------------------------------------------------
def test_csp_flags_unsafe_inline():
    t = parse_target("http://example.com")
    resp = FakeResp(200, "<html></html>",
                    {"Content-Security-Policy": "default-src 'self'; "
                     "script-src 'self' 'unsafe-inline'"})
    findings = CspAnalyzerCheck().run(t, _FakeHttp(resp), CrawlData(), Config())
    assert findings and "unsafe-inline" in findings[0].evidence


def test_csp_no_finding_when_absent():
    t = parse_target("http://example.com")
    findings = CspAnalyzerCheck().run(t, _FakeHttp(FakeResp(200, "", {})),
                                      CrawlData(), Config())
    assert findings == []


# ---- WAF detection ------------------------------------------------------
def test_waf_detects_cloudflare():
    t = parse_target("http://example.com")
    resp = FakeResp(200, "", {"Server": "cloudflare", "CF-RAY": "abc"})
    findings = WafCdnCheck().run(t, _FakeHttp(resp), CrawlData(), Config())
    assert findings and "Cloudflare" in findings[0].title


# ---- web_recon (security.txt / SRI / comments) --------------------------
def test_web_recon_flags_missing_securitytxt_and_comment():
    t = parse_target("http://example.com")
    html = ('<html><script src="https://cdn.other.com/a.js"></script>'
            '<!-- TODO: remove admin backdoor password=123 --></html>')
    findings = WebReconCheck().run(t, _FakeHttp(FakeResp(200, html)),
                                   CrawlData(), Config())
    titles = " ".join(f.title for f in findings)
    assert "security.txt" in titles
    assert "Subresource Integrity" in titles       # external script, no integrity
    assert "HTML comments" in titles               # sensitive comment

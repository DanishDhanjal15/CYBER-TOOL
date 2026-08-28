"""Tests for the six advanced features (JS/secrets, recon, templates, OAST,
protocol checks, headless browser graceful-degrade)."""
from webrecon.data.secret_patterns import SECRET_PATTERNS
from webrecon.templates_engine.engine import _eval_request, run_templates, load_templates
from webrecon.oast import OASTServer
from webrecon.checks.graphql import GraphqlCheck
from webrecon.browser.domxss import BrowserDomXssCheck
from webrecon.core.config import Config
from webrecon.core.crawler import CrawlData
from webrecon.core.target import parse_target


class FakeResponse:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}
        self.url = "http://example.com/"


class FakeHttp:
    def __init__(self, response):
        self._r = response

    def get(self, url, **k):
        return self._r

    def post(self, url, **k):
        return self._r

    def request(self, m, url, **k):
        return self._r

    head = get


# ---- Feature 1: secret catalog ------------------------------------------
def test_secret_catalog_matches_aws_and_github():
    text = "key=AKIAIOSFODNN7EXAMPLE token=ghp_" + "a" * 36
    hits = [name for (name, _s, _c, rx) in SECRET_PATTERNS if rx.search(text)]
    assert "AWS Access Key" in hits
    assert "GitHub Classic PAT" in hits


def test_secret_catalog_no_false_positive_on_plain_text():
    hits = [n for (n, _s, _c, rx) in SECRET_PATTERNS
            if rx.search("just some normal words here")]
    assert hits == []


# ---- Feature 3: template engine -----------------------------------------
def test_template_matcher_and_condition():
    req = {"matchers-condition": "and", "matchers": [
        {"type": "status", "status": [200]},
        {"type": "word", "part": "body", "words": ["[core]"]}]}
    assert _eval_request(FakeResponse("[core]\n", 200), req) is True
    assert _eval_request(FakeResponse("nope", 200), req) is False
    assert _eval_request(FakeResponse("[core]", 404), req) is False


def test_bundled_templates_load():
    tpls = load_templates()
    ids = {t["id"] for t in tpls}
    assert "exposed-env-file" in ids and "exposed-git-config" in ids


def test_template_run_produces_finding():
    t = parse_target("http://example.com")
    resp = FakeResponse("[core]\nrepositoryformatversion = 0", 200)
    tpls = [{"id": "x", "info": {"name": "git", "severity": "high"},
             "requests": [{"method": "GET", "path": ["/.git/config"],
                           "matchers": [{"type": "word", "part": "body",
                                         "words": ["[core]"]}]}]}]
    findings = run_templates(t, FakeHttp(resp), tpls)
    assert len(findings) == 1 and findings[0].severity.value == "HIGH"


# ---- Feature 4: OAST -----------------------------------------------------
def test_oast_records_interactions():
    srv = OASTServer()
    try:
        tok = srv.new_token()
        assert srv.interactions(tok) == []
        srv.record(tok, {"path": f"/{tok}"})
        assert len(srv.interactions(tok)) == 1
        assert srv.total() == 1
        assert tok in srv.url_for(tok)
    finally:
        srv.stop()


# ---- Feature 5: GraphQL --------------------------------------------------
def test_graphql_introspection_detected():
    t = parse_target("http://example.com")
    resp = FakeResponse('{"data":{"__schema":{"queryType":{"name":"Query"}}}}')
    findings = GraphqlCheck().run(t, FakeHttp(resp), CrawlData(), Config())
    assert findings and any("introspection" in f.title.lower() for f in findings)


# ---- Feature 6: headless browser graceful degrade -----------------------
def test_browser_check_noop_without_flag():
    t = parse_target("http://example.com")
    cfg = Config()  # browser=False
    assert BrowserDomXssCheck().run(t, FakeHttp(FakeResponse()), CrawlData(), cfg) == []

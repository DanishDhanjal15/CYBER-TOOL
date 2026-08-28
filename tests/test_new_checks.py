"""Tests for the Strix-inspired additions: SSTI, JWT, PoC/confidence."""
from webrecon.checks.ssti import SstiCheck
from webrecon.checks.jwt_check import JwtCheck
from webrecon.checks._inject import InjectionPoint, build_poc
from webrecon.core.config import Config
from webrecon.core.crawler import CrawlData
from webrecon.core.target import parse_target


class FakeResponse:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}
        self.url = "http://example.com/"


class ScriptedHttp:
    """Returns responses based on whether a payload appears in the URL/query."""
    def __init__(self, echo=False, eval_math=False, home_text=""):
        self.echo = echo
        self.eval_math = eval_math
        self.home_text = home_text

    def get(self, url, **kwargs):
        if self.home_text and url.endswith("/"):
            return FakeResponse(text=self.home_text)
        # Simulate a template engine that evaluates 7*7 -> 49.
        if self.eval_math and ("7*7" in url or "7%2A7" in url):
            return FakeResponse(text="Hello 49")
        if self.echo:
            return FakeResponse(text=f"reflected {url}")
        return FakeResponse(text="ok")

    request = get
    post = get
    head = get


def _crawl_with_param():
    c = CrawlData()
    url = "http://example.com/render?name=guest"
    c.urls.append(url)
    c.params[url] = ["name"]
    return c


def test_ssti_confirms_on_eval():
    t = parse_target("http://example.com")
    findings = SstiCheck().run(t, ScriptedHttp(eval_math=True), _crawl_with_param(),
                               Config())
    assert len(findings) == 1
    assert findings[0].confidence == "CONFIRMED"
    assert "template" in findings[0].title.lower()


def test_ssti_no_false_positive_on_reflection():
    # Server merely reflects the payload; 7*7 is echoed but never becomes 49.
    t = parse_target("http://example.com")
    findings = SstiCheck().run(t, ScriptedHttp(echo=True), _crawl_with_param(),
                               Config())
    assert findings == []


def test_jwt_alg_none_detected():
    # header {"alg":"none"} . payload {"user":"admin"} .
    token = ("eyJhbGciOiJub25lIn0."
             "eyJ1c2VyIjoiYWRtaW4ifQ.")
    t = parse_target("http://example.com")
    http = ScriptedHttp(home_text=f"<html>tok={token}</html>")
    findings = JwtCheck().run(t, http, CrawlData(), Config())
    titles = " ".join(f.title for f in findings)
    assert "alg: none" in titles
    assert "no expiry" in titles.lower()


def test_build_poc_get_and_post():
    get_pt = InjectionPoint("query", "http://example.com/x", "get", "q",
                            {"q": "1"})
    assert build_poc(get_pt, "PAY").startswith("curl -i 'http://example.com/x?")
    post_pt = InjectionPoint("form", "http://example.com/f", "post", "u",
                             {"u": "1", "p": "2"})
    poc = build_poc(post_pt, "PAY")
    assert "-X POST" in poc and "u=PAY" in poc

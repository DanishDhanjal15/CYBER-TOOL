"""Tests for rate-limit detection + algorithm recommendation."""
from webrecon.analysis.ratelimit_advisor import classify, recommend
from webrecon.checks.ratelimit import RateLimitCheck
from webrecon.core.config import Config
from webrecon.core.crawler import CrawlData, Form
from webrecon.core.target import parse_target


class Resp:
    def __init__(self, status=200, text="", headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}


class OpenHttp:
    """Never rate-limits."""
    def get(self, u, **k):
        return Resp(200, "ok")
    def post(self, u, **k):
        return Resp(200, "ok")
    request = get


class LimitedHttp:
    """429 after 5 requests."""
    def __init__(self):
        self.n = 0
    def get(self, u, **k):
        self.n += 1
        if self.n > 5:
            return Resp(429, "Too Many Requests",
                        {"Retry-After": "30", "X-RateLimit-Limit": "5"})
        return Resp(200, "ok")
    def post(self, u, **k):
        return self.get(u, **k)
    request = get


# ---- advisor ------------------------------------------------------------
def test_classify_and_recommend():
    assert classify("http://x/login") == "auth"
    assert classify("http://x/api/v1/users") == "api"
    assert classify("http://x/profile?id=1") == "general"   # not 'upload'
    rec = recommend("http://x/login")
    assert "Sliding Window" in rec["algo"] and rec["endpoint_type"] == "auth"
    assert "Token Bucket" in recommend("http://x/api/v1/x")["algo"]


# ---- detection ----------------------------------------------------------
def _crawl():
    c = CrawlData()
    c.params["http://127.0.0.1:8099/search?q=1"] = ["q"]
    c.forms.append(Form(action="http://127.0.0.1:8099/login", method="post",
                        inputs={"username": "t", "password": "t"}))
    return c


def test_no_rate_limiting_flags_auth_high():
    t = parse_target("http://127.0.0.1")
    cfg = Config(); cfg.rl_burst = 8
    findings = RateLimitCheck().run(t, OpenHttp(), _crawl(), cfg)
    auth = [f for f in findings if "auth endpoint" in f.title]
    assert auth and auth[0].severity.value == "HIGH"
    assert "Sliding Window" in auth[0].remediation
    # a search endpoint gets a leaky-bucket recommendation
    search = [f for f in findings if "search endpoint" in f.title]
    assert search and "Leaky Bucket" in search[0].remediation


def test_rate_limiting_detected_reports_info():
    t = parse_target("http://127.0.0.1")
    cfg = Config(); cfg.rl_burst = 12
    findings = RateLimitCheck().run(t, LimitedHttp(), _crawl(), cfg)
    active = [f for f in findings if "active" in f.title.lower()]
    assert active and active[0].severity.value == "INFO"
    assert "429" in active[0].evidence or "Retry-After" in active[0].evidence

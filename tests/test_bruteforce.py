"""Tests for the opt-in brute-force / weak-credential audit."""
from webrecon.checks.bruteforce import BruteForceCheck
from webrecon.core.config import Config
from webrecon.core.crawler import CrawlData, Form
from webrecon.core.target import parse_target


class FakeResp:
    def __init__(self, status=200, text="", headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}


class LoginHttp:
    """Accepts admin/admin123 (302 + session); everything else = 200 'Invalid'."""
    def post(self, url, data=None, **k):
        data = data or {}
        if data.get("username") == "admin" and data.get("password") == "admin123":
            return FakeResp(302, "", {"Location": "/dashboard",
                                      "Set-Cookie": "auth=ok"})
        return FakeResp(200, "Invalid credentials, try again")

    def get(self, url, **k):
        return FakeResp(200, "")
    request = get


class AlwaysFailHttp:
    def post(self, url, data=None, **k):
        return FakeResp(200, "Invalid credentials")
    def get(self, url, **k):
        return FakeResp(200, "")
    request = get


def _login_crawl():
    c = CrawlData()
    c.forms.append(Form(action="http://x/login", method="post",
                        inputs={"username": "test", "password": "test"}))
    return c


def test_bruteforce_is_opt_in_only():
    t = parse_target("http://example.com")
    cfg = Config()  # bruteforce not enabled
    assert BruteForceCheck().run(t, LoginHttp(), _login_crawl(), cfg) == []


def test_bruteforce_finds_weak_credential():
    t = parse_target("http://example.com")
    cfg = Config(); cfg.bruteforce = True; cfg.max_attempts = 300
    findings = BruteForceCheck().run(t, LoginHttp(), _login_crawl(), cfg)
    assert any(f.severity.value == "CRITICAL" and "admin" in f.title
               for f in findings)
    weak = next(f for f in findings if f.severity.value == "CRITICAL")
    assert "admin123" in weak.evidence


def test_bruteforce_flags_no_protection():
    t = parse_target("http://example.com")
    cfg = Config(); cfg.bruteforce = True; cfg.max_attempts = 50
    findings = BruteForceCheck().run(t, AlwaysFailHttp(), _login_crawl(), cfg)
    assert any("no brute-force protection" in f.title.lower() for f in findings)


def test_no_login_form_no_findings():
    t = parse_target("http://example.com")
    cfg = Config(); cfg.bruteforce = True
    assert BruteForceCheck().run(t, LoginHttp(), CrawlData(), cfg) == []

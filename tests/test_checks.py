from webrecon.checks.security_headers import SecurityHeadersCheck
from webrecon.checks.cors import CorsCheck
from webrecon.core.config import Config
from webrecon.core.crawler import CrawlData
from webrecon.core.target import parse_target


class FakeResponse:
    def __init__(self, headers=None, status_code=200, text=""):
        self.headers = headers or {}
        self.status_code = status_code
        self.text = text
        self.url = "http://example.com/"


class FakeHttp:
    """Minimal stand-in for HttpClient returning a canned response."""
    def __init__(self, response):
        self._response = response

    def get(self, url, **kwargs):
        return self._response

    def request(self, method, url, **kwargs):
        return self._response

    post = get
    head = get


def test_security_headers_flags_missing():
    target = parse_target("https://example.com")
    http = FakeHttp(FakeResponse(headers={"Server": "nginx"}))
    findings = SecurityHeadersCheck().run(target, http, CrawlData(), Config())
    titles = " ".join(f.title for f in findings)
    assert "Content-Security-Policy" in titles
    assert "Strict-Transport-Security" in titles
    # 6 tracked headers all absent
    assert len(findings) == 6


def test_security_headers_no_findings_when_present():
    target = parse_target("https://example.com")
    headers = {
        "content-security-policy": "default-src 'self'",
        "strict-transport-security": "max-age=31536000",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "geolocation=()",
    }
    http = FakeHttp(FakeResponse(headers=headers))
    findings = SecurityHeadersCheck().run(target, http, CrawlData(), Config())
    assert findings == []


def test_cors_reflected_origin_with_credentials_is_high():
    target = parse_target("https://example.com")
    resp = FakeResponse(headers={
        "Access-Control-Allow-Origin": "https://webrecon-evil.example",
        "Access-Control-Allow-Credentials": "true",
    })
    findings = CorsCheck().run(target, FakeHttp(resp), CrawlData(), Config())
    assert len(findings) == 1
    assert findings[0].severity.value == "HIGH"

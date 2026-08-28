import pytest
from webrecon.core.target import parse_target, TargetError


def test_parse_ip():
    t = parse_target("127.0.0.1")
    assert t.is_ip is True
    assert t.host == "127.0.0.1"
    assert t.scheme == "http"
    assert t.base_url == "http://127.0.0.1"
    assert t.ip_addresses == ["127.0.0.1"]


def test_parse_https_url_with_path_is_normalised():
    t = parse_target("https://example.com/some/path?x=1")
    assert t.scheme == "https"
    assert t.host == "example.com"
    assert t.port == 443
    assert t.base_url == "https://example.com"
    assert t.url("/a") == "https://example.com/a"


def test_explicit_port_preserved():
    t = parse_target("http://127.0.0.1:8080")
    assert t.port == 8080
    assert t.base_url == "http://127.0.0.1:8080"


def test_in_scope():
    t = parse_target("http://example.com")
    assert t.in_scope("http://example.com/a") is True
    assert t.in_scope("http://evil.com/a") is False


def test_bad_scheme_rejected():
    with pytest.raises(TargetError):
        parse_target("ftp://example.com")

"""Tests for the developer-first features: fix, badge, watch."""
import time
from pathlib import Path

from webrecon import remediate, badge, watch
from webrecon.model.finding import Finding, ScanResult
from webrecon.model.severity import Severity


def _result_with(findings, server="nginx/1.20"):
    r = ScanResult(target="http://x", started_at="t")
    r.recon = {"fingerprint": {"headers": {"Server": server}}}
    r.extend(findings)
    return r


# ---- remediation --------------------------------------------------------
def test_detect_stack():
    assert remediate.detect_stack(_result_with([], "nginx/1.20")) == "nginx"
    assert remediate.detect_stack(_result_with([], "Apache/2.4")) == "apache"
    assert remediate.detect_stack(_result_with([], "gunicorn/20")) == "flask"


def test_generate_header_fixes_nginx():
    f = Finding(id="SEC-HEADERS-001", title="Missing Content-Security-Policy",
                severity=Severity.MEDIUM, location="http://x/")
    text, n = remediate.generate(_result_with([f]), "nginx")
    assert n == 1
    assert 'add_header Content-Security-Policy "default-src \'self\'" always;' in text


def test_generate_multi_stack():
    f = Finding(id="SEC-HEADERS-003", title="Missing X-Frame-Options",
                severity=Severity.LOW, location="http://x/")
    assert 'Header always set X-Frame-Options "DENY"' in \
        remediate.generate(_result_with([f]), "apache")[0]
    assert 'res.setHeader("X-Frame-Options", "DENY");' in \
        remediate.generate(_result_with([f]), "express")[0]


def test_generate_nothing_to_fix():
    text, n = remediate.generate(_result_with([]), "nginx")
    assert n == 0 and "nothing to remediate" in text.lower()


# ---- badge --------------------------------------------------------------
def test_badge_grades():
    assert badge.grade({"CRITICAL": 1}) == "F"
    assert badge.grade({"HIGH": 2}) == "D"
    assert badge.grade({"MEDIUM": 1}) == "C"
    assert badge.grade({"LOW": 3}) == "B"
    assert badge.grade({"INFO": 5}) == "A"


def test_badge_svg_valid():
    svg = badge._svg("A")
    assert svg.startswith("<svg") and "security" in svg and ">A<" in svg


# ---- watch --------------------------------------------------------------
def test_dir_signature_changes_on_write(tmp_path):
    (tmp_path / "a.py").write_text("x", encoding="utf-8")
    sig1 = watch._dir_signature(str(tmp_path))
    time.sleep(0.05)
    (tmp_path / "b.py").write_text("y", encoding="utf-8")
    sig2 = watch._dir_signature(str(tmp_path))
    assert sig2 >= sig1 and sig1 > 0

"""Tests for the pre-deploy security gate (auto-detect + git hook)."""
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from webrecon import predeploy


class _H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")


def test_detect_local_app_finds_running_server():
    # start a server on a known dev port from the probe list
    port = 5001
    srv = ThreadingHTTPServer(("127.0.0.1", port), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.3)
    try:
        found = predeploy.detect_local_app(ports=[9999, port, 4321])
        assert f"http://127.0.0.1:{port}" in found
        assert "http://127.0.0.1:9999" not in found   # nothing listening there
    finally:
        srv.shutdown()


def test_detect_returns_empty_when_nothing_running():
    assert predeploy.detect_local_app(ports=[59998, 59999]) == []


def test_gate_thresholds():
    # HIGH gate must include CRITICAL + HIGH but not MEDIUM
    assert predeploy._RANK["CRITICAL"] >= predeploy._RANK["HIGH"]
    assert predeploy._RANK["HIGH"] > predeploy._RANK["MEDIUM"]


def test_install_hook_writes_pre_push(tmp_path, monkeypatch):
    (tmp_path / ".git" / "hooks").mkdir(parents=True)
    monkeypatch.chdir(tmp_path)

    class _C:
        def print(self, *a, **k):
            pass
    rc = predeploy.install_hook(_C())
    hook = tmp_path / ".git" / "hooks" / "pre-push"
    assert rc == 0 and hook.exists()
    body = hook.read_text(encoding="utf-8")
    assert "webrecon predeploy" in body and "--fail-on high" in body


def test_install_hook_fails_without_git(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)   # no .git here

    class _C:
        def print(self, *a, **k):
            pass
    assert predeploy.install_hook(_C()) == 2

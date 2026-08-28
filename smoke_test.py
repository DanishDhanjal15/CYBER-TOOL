#!/usr/bin/env python3
"""WebRecon smoke test — a quick, self-contained end-to-end sanity check.

It verifies the tool is "alive": the CLI runs, checks are registered, the unit
tests pass, and a real scan against a tiny built-in vulnerable server produces
findings and writes reports. It needs no network and no external server.

Run:
    python smoke_test.py            # full smoke test
    python smoke_test.py --no-tests # skip the pytest step (faster)

Exit code 0 = everything works, non-zero = something is broken.
"""
from __future__ import annotations

import socket
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

RESULTS: list[tuple[bool, str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((ok, name, detail))
    mark = "\033[92mPASS\033[0m" if ok else "\033[91mFAIL\033[0m"
    print(f"  [{mark}] {name}" + (f" — {detail}" if detail else ""))


# --- A tiny intentionally-weak server (missing headers + reflects a param) ---
class _Vuln(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def do_GET(self):
        q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
        body = f"<html><body>Search results for: {q}</body></html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", "SESSIONID=test123")  # insecure cookie
        self.end_headers()
        self.wfile.write(body)


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def main() -> int:
    skip_tests = "--no-tests" in sys.argv
    print("===== WebRecon smoke test =====")

    # 1) CLI runs (--version)
    try:
        out = subprocess.run([sys.executable, "-m", "webrecon", "--version"],
                             capture_output=True, text=True, timeout=30)
        ok = out.returncode == 0 and "webrecon" in (out.stdout + out.stderr).lower()
        check("CLI runs (--version)", ok, (out.stdout or out.stderr).strip()[:40])
    except Exception as exc:
        check("CLI runs (--version)", False, str(exc))

    # 2) Checks are registered
    try:
        import webrecon.checks as c
        n = len(c.available_names())
        check("Checks registered", n >= 10, f"{n} checks")
    except Exception as exc:
        check("Checks registered", False, str(exc))

    # 3) Unit tests pass (optional)
    if skip_tests:
        print("  [ .. ] Unit tests — skipped (--no-tests)")
    else:
        try:
            out = subprocess.run([sys.executable, "-m", "pytest", "-q"],
                                 capture_output=True, text=True, timeout=180)
            last = (out.stdout.strip().splitlines() or ["no output"])[-1]
            check("Unit tests pass", out.returncode == 0, last)
        except Exception as exc:
            check("Unit tests pass", False, str(exc))

    # 4) End-to-end scan against a built-in vulnerable server
    try:
        from webrecon.core.config import Config
        from webrecon.core.target import parse_target
        from webrecon.engine import Engine

        port = _free_port()
        httpd = ThreadingHTTPServer(("127.0.0.1", port), _Vuln)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()

        class _Silent:
            def print(self, *a, **k):
                pass

        outdir = tempfile.mkdtemp(prefix="webrecon_smoke_")
        cfg = Config()
        cfg.apply_overrides(depth=1, max_urls=10, authorized=True,
                            output_dir=outdir, formats=["html", "json"])
        target = parse_target(f"http://127.0.0.1:{port}")
        result = Engine(target, cfg, console=_Silent()).run()
        httpd.shutdown()

        n = len(result.findings)
        check("Scan completes with findings", n > 0, f"{n} findings")

        # 5) Reports were written
        from webrecon.report import write_all
        paths = write_all(result, outdir, "smoke", ["html", "json"])
        html_ok = paths.get("html") and paths["html"].exists()
        json_ok = paths.get("json") and paths["json"].exists()
        check("Reports generated (HTML + JSON)", bool(html_ok and json_ok),
              f"{outdir}")
    except Exception as exc:
        check("Scan completes with findings", False, str(exc))
        check("Reports generated (HTML + JSON)", False, "skipped")

    # Summary
    passed = sum(1 for ok, _, _ in RESULTS if ok)
    total = len(RESULTS)
    print("=" * 31)
    if passed == total:
        print(f"\033[92mSMOKE TEST PASSED\033[0m  ({passed}/{total})")
        return 0
    print(f"\033[91mSMOKE TEST FAILED\033[0m  ({passed}/{total} passed)")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

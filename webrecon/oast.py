"""A minimal OAST (out-of-band application security testing) HTTP listener.

Blind vulnerabilities — SSRF, OS-command injection, XXE — can't be confirmed
in-band because the injected action produces no visible response change. The
classic solution (Burp Collaborator / interactsh) is a server the target is
tricked into calling; a recorded callback proves the vulnerability.

This is a self-contained, threaded HTTP listener. Each injection gets a unique
token embedded in a callback URL; if the target fetches it, we record the hit
and upgrade the finding to CONFIRMED.

For it to catch a *real* external blind vuln, the listener must be reachable
from the target (a public host/port). For localhost testing it proves the
mechanism end-to-end.
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _record(self):
        server: "OASTServer" = self.server.oast  # type: ignore[attr-defined]
        token = self.path.strip("/").split("/")[0].split("?")[0]
        if token:
            server.record(token, {
                "path": self.path,
                "method": self.command,
                "client": self.client_address[0],
                "ua": self.headers.get("User-Agent", ""),
            })
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_GET(self):
        self._record()

    def do_POST(self):
        self._record()


class OASTServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 0,
                 public_host: str | None = None):
        self._httpd = ThreadingHTTPServer((host, port), _Handler)
        self._httpd.oast = self  # type: ignore[attr-defined]
        self.host = host
        self.port = self._httpd.server_address[1]
        # public_host lets you advertise a reachable address to the target.
        self.public = public_host or f"{host}:{self.port}"
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._hits: dict[str, list[dict]] = {}
        self._counter = 0

    # -- lifecycle
    def start(self) -> None:
        self._thread = threading.Thread(target=self._httpd.serve_forever,
                                        daemon=True)
        self._thread.start()

    def stop(self) -> None:
        try:
            # shutdown() blocks unless serve_forever() is actually running.
            if self._thread is not None and self._thread.is_alive():
                self._httpd.shutdown()
            self._httpd.server_close()
        except Exception:
            pass

    # -- token API
    def new_token(self) -> str:
        with self._lock:
            self._counter += 1
            token = f"wr{self._counter:06d}oast"
            self._hits.setdefault(token, [])
        return token

    def url_for(self, token: str) -> str:
        return f"http://{self.public}/{token}"

    def host_for(self, token: str) -> str:
        """Bare host:port/token form for shell payloads."""
        return f"{self.public}/{token}"

    def record(self, token: str, meta: dict) -> None:
        with self._lock:
            self._hits.setdefault(token, []).append(meta)

    def interactions(self, token: str) -> list[dict]:
        with self._lock:
            return list(self._hits.get(token, []))

    def total(self) -> int:
        with self._lock:
            return sum(len(v) for v in self._hits.values())

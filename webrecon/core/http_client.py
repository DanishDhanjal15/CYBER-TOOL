"""A thin, safety-conscious wrapper around requests.Session.

Adds: consistent User-Agent, timeouts, optional rate limiting, retry-on-error,
a shared request counter, and TLS-verify toggling (scanners routinely hit
self-signed / expired certs and should not hard-fail on them).
"""
from __future__ import annotations

import threading
import time
import urllib3

import requests

from .config import Config

# We deliberately allow scanning hosts with broken TLS; silence the noise.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class HttpClient:
    def __init__(self, config: Config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": config.user_agent})
        # Authenticated / grey-box scanning: custom headers + cookie on every req.
        if getattr(config, "extra_headers", None):
            self.session.headers.update(config.extra_headers)
        if getattr(config, "cookie", ""):
            self.session.headers["Cookie"] = config.cookie
        self._lock = threading.Lock()
        self._last_request = 0.0
        self.request_count = 0

    def _throttle(self) -> None:
        if self.config.rate_limit and self.config.rate_limit > 0:
            min_interval = 1.0 / self.config.rate_limit
            with self._lock:
                wait = min_interval - (time.monotonic() - self._last_request)
                if wait > 0:
                    time.sleep(wait)
                self._last_request = time.monotonic()

    def request(self, method: str, url: str, *, retries: int = 1, **kwargs):
        """Perform a request. Returns a Response or None on failure."""
        self._throttle()
        kwargs.setdefault("timeout", self.config.timeout)
        kwargs.setdefault("verify", self.config.verify_tls)
        kwargs.setdefault("allow_redirects", False)
        last_exc: Exception | None = None
        for attempt in range(retries + 1):
            try:
                with self._lock:
                    self.request_count += 1
                return self.session.request(method, url, **kwargs)
            except requests.RequestException as exc:
                last_exc = exc
                if attempt < retries:
                    time.sleep(0.5 * (attempt + 1))
        if self.config.verbose and last_exc is not None:
            print(f"  [http] {method} {url} failed: {last_exc}")
        return None

    def get(self, url: str, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs):
        return self.request("POST", url, **kwargs)

    def head(self, url: str, **kwargs):
        return self.request("HEAD", url, **kwargs)

    def close(self) -> None:
        self.session.close()

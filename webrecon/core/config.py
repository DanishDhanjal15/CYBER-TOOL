"""Scan configuration — defaults, YAML file, and CLI overrides merged together."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


DEFAULT_UA = "WebRecon/0.1 (+authorized-security-scan)"


@dataclass
class Config:
    target: str = ""
    output_dir: str = "./reports"
    formats: list[str] = field(default_factory=lambda: ["console", "html", "json"])
    checks: list[str] | None = None        # None => all checks
    aggressive: bool = False
    threads: int = 10
    timeout: int = 10
    rate_limit: float = 0.0                 # requests/sec cap; 0 => unlimited
    depth: int = 2
    max_urls: int = 200
    user_agent: str = DEFAULT_UA
    respect_robots: bool = False
    verbose: bool = False
    authorized: bool = False
    verify_tls: bool = False                # scanners often hit bad certs; don't hard-fail
    # Authenticated / grey-box scanning (sent on every request):
    extra_headers: dict = field(default_factory=dict)
    cookie: str = ""                        # raw Cookie header value
    # API-spec ingestion + scan profile:
    openapi: str = ""                       # path or URL to an OpenAPI/Swagger doc
    templates_dir: str = ""                 # extra directory of YAML templates
    profile: str = ""                       # "", quick, standard, deep
    # Out-of-band (blind vuln) testing:
    oast: bool = False                      # start a local OAST listener
    oast_host: str = ""                     # public host:port to advertise to target
    browser: bool = False                   # enable headless-browser DOM checks
    cve_db: str = ""                        # path to a custom CVE JSON DB
    # Weak-credential / brute-force audit (opt-in, authorized only):
    bruteforce: bool = False                # enable the login brute-force check
    wordlist: str = ""                      # password list (default: bundled top-100)
    username: str = ""                      # comma list of usernames to try
    max_attempts: int = 200                 # hard cap on total login attempts
    rl_burst: int = 20                      # requests per rate-limit probe burst
    wayback: bool = False                   # pull historical URLs from the Wayback Machine
    local_scan: bool = False                # dev/localhost mode — skip external recon
    fail_on: str = ""                       # predeploy gate: min severity to fail on
    # Scan history / diff:
    db: str = "webrecon.db"                 # SQLite history database
    no_store: bool = False                  # skip saving to history
    diff: bool = False                      # show New/Fixed vs previous scan
    baseline: bool = False                  # mark this scan as the baseline

    def apply_profile(self) -> "Config":
        """Expand a named profile into concrete settings (explicit CLI flags,
        applied afterwards, still win)."""
        p = (self.profile or "").lower()
        if p == "quick":
            self.depth, self.max_urls, self.aggressive = 1, 40, False
        elif p == "standard":
            self.depth, self.max_urls, self.aggressive = 2, 150, False
        elif p == "deep":
            self.depth, self.max_urls, self.aggressive = 3, 400, True
        return self

    @classmethod
    def from_yaml(cls, path: str | Path) -> "Config":
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        cfg = cls()
        for key, value in data.items():
            if hasattr(cfg, key) and value is not None:
                setattr(cfg, key, value)
        return cfg

    def apply_overrides(self, **overrides) -> "Config":
        for key, value in overrides.items():
            if value is None:
                continue
            if hasattr(self, key):
                setattr(self, key, value)
        return self

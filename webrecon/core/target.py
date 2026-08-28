"""Target parsing, validation, and DNS resolution.

Accepts a URL (http/https), a bare hostname, or an IP address and normalises
it into a consistent Target object that the rest of the scanner uses.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urlparse, urlunparse


@dataclass
class Target:
    raw: str
    scheme: str
    host: str                       # hostname or IP as given
    port: int
    base_url: str                   # scheme://host[:port]
    is_ip: bool = False
    ip_addresses: list[str] = field(default_factory=list)

    def url(self, path: str = "/") -> str:
        if not path.startswith("/"):
            path = "/" + path
        return self.base_url + path

    def in_scope(self, url: str) -> bool:
        """Same host only (keeps the crawler from wandering off-site)."""
        try:
            netloc = urlparse(url).netloc.lower()
        except Exception:
            return False
        host = netloc.split("@")[-1].split(":")[0]
        return host == self.host.lower()


class TargetError(ValueError):
    pass


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def parse_target(raw: str, default_scheme: str = "http") -> Target:
    raw = raw.strip()
    if not raw:
        raise TargetError("Empty target.")

    # Add a scheme so urlparse populates netloc rather than path.
    if "://" not in raw:
        candidate = f"{default_scheme}://{raw}"
    else:
        candidate = raw

    parsed = urlparse(candidate)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise TargetError(f"Unsupported scheme: {scheme!r} (use http or https).")

    host = parsed.hostname
    if not host:
        raise TargetError(f"Could not parse a host from {raw!r}.")

    is_ip = _looks_like_ip(host)
    port = parsed.port or (443 if scheme == "https" else 80)

    # Rebuild a clean base URL (drop path/query/fragment; keep explicit ports).
    default_port = 443 if scheme == "https" else 80
    netloc = host if port == default_port else f"{host}:{port}"
    base_url = urlunparse((scheme, netloc, "", "", "", ""))

    ip_addresses: list[str] = []
    if is_ip:
        ip_addresses = [host]
    else:
        try:
            infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
            ip_addresses = sorted({info[4][0] for info in infos})
        except socket.gaierror as exc:
            raise TargetError(f"DNS resolution failed for {host!r}: {exc}") from exc

    return Target(
        raw=raw,
        scheme=scheme,
        host=host,
        port=port,
        base_url=base_url,
        is_ip=is_ip,
        ip_addresses=ip_addresses,
    )

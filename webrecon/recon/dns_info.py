"""DNS information gathering: A/AAAA/MX/NS/TXT records and reverse DNS."""
from __future__ import annotations

import socket

try:
    import dns.resolver
    import dns.reversename
    _HAS_DNSPYTHON = True
except Exception:  # pragma: no cover
    _HAS_DNSPYTHON = False

from webrecon.core.target import Target


_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def gather(target: Target) -> dict:
    info: dict = {"host": target.host, "ip_addresses": target.ip_addresses,
                  "records": {}, "reverse_dns": {}}
    if target.is_ip:
        info["records"] = {"note": "target is an IP; skipping name records"}
    elif _HAS_DNSPYTHON:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5.0
        for rtype in _RECORD_TYPES:
            try:
                answers = resolver.resolve(target.host, rtype)
                info["records"][rtype] = [r.to_text() for r in answers]
            except Exception:
                continue
    else:
        info["records"] = {"note": "dnspython not installed; limited DNS info"}

    for ip in target.ip_addresses:
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            info["reverse_dns"][ip] = host
        except Exception:
            info["reverse_dns"][ip] = None
    return info

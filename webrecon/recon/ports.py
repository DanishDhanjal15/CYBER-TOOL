"""Lightweight TCP port scan + banner grab over common ports.

Uses plain sockets and a thread pool. Non-destructive: a connect scan only.
"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from webrecon.core.target import Target


# port -> service label
COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios",
    143: "imap", 443: "https", 445: "smb", 465: "smtps", 587: "submission",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs",
    3000: "node/dev", 3306: "mysql", 3389: "rdp", 5432: "postgres",
    5601: "kibana", 5900: "vnc", 6379: "redis", 8000: "http-alt",
    8080: "http-proxy", 8443: "https-alt", 8888: "http-alt", 9200: "elasticsearch",
    27017: "mongodb",
}


def _probe(ip: str, port: int, timeout: float) -> tuple[int, str | None]:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            banner = None
            try:
                sock.settimeout(timeout)
                data = sock.recv(128)
                if data:
                    banner = data.decode("latin-1", "replace").strip()
            except Exception:
                pass
            return port, banner or ""
    except Exception:
        return port, None


def scan(target: Target, *, timeout: float = 1.5, threads: int = 40) -> dict:
    ip = target.ip_addresses[0] if target.ip_addresses else target.host
    open_ports: dict[int, dict] = {}
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(_probe, ip, port, timeout) for port in COMMON_PORTS]
        for fut in as_completed(futures):
            port, banner = fut.result()
            if banner is not None:
                open_ports[port] = {
                    "service": COMMON_PORTS.get(port, "unknown"),
                    "banner": banner,
                }
    return {
        "ip": ip,
        "open_ports": dict(sorted(open_ports.items())),
        "scanned": len(COMMON_PORTS),
    }

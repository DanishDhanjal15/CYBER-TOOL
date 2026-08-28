"""Render captured transactions as raw HTTP, and attach req/resp to findings.

Gives every finding a ZAP-style raw request + raw response for its evidence,
matched from the scanner's traffic log by URL.
"""
from __future__ import annotations

from urllib.parse import urlparse


def render_request(txn: dict) -> str:
    p = urlparse(txn.get("url", ""))
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    lines = [f"{txn.get('method', 'GET')} {path} HTTP/1.1",
             f"Host: {p.netloc}"]
    for k, v in (txn.get("req_headers") or {}).items():
        if k.lower() == "host":
            continue
        lines.append(f"{k}: {v}")
    body = txn.get("req_body") or ""
    return "\n".join(lines) + "\n\n" + body


def render_response(txn: dict) -> str:
    status = txn.get("status", 0)
    lines = [f"HTTP/1.1 {status}"]
    for k, v in (txn.get("resp_headers") or {}).items():
        lines.append(f"{k}: {v}")
    body = txn.get("resp_body") or ""
    return "\n".join(lines) + "\n\n" + body


def _path(url: str) -> str:
    p = urlparse(url)
    return f"{p.netloc}{p.path}"


def attach_evidence(findings, transactions) -> None:
    """Attach the best-matching raw request/response to each finding."""
    if not transactions:
        return
    by_url: dict[str, dict] = {}
    by_path: dict[str, dict] = {}
    for t in transactions:            # later entries overwrite -> most recent wins
        by_url[t.get("url", "")] = t
        by_path[_path(t.get("url", ""))] = t

    for f in findings:
        loc = f.location or ""
        txn = by_url.get(loc) or by_path.get(_path(loc))
        if txn is None and loc:
            # last resort: any transaction whose url starts with the location
            for t in reversed(transactions):
                if t.get("url", "").startswith(loc.split("?")[0]):
                    txn = t
                    break
        if txn:
            f.request_raw = render_request(txn)
            f.response_raw = render_response(txn)

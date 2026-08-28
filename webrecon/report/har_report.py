"""Export the scan's HTTP traffic log as HAR 1.2 (openable in Chrome/Burp)."""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse, parse_qsl


def _headers(d: dict) -> list[dict]:
    return [{"name": str(k), "value": str(v)} for k, v in (d or {}).items()]


def _entry(txn: dict) -> dict:
    url = txn.get("url", "")
    q = parse_qsl(urlparse(url).query)
    req = {
        "method": txn.get("method", "GET"),
        "url": url,
        "httpVersion": "HTTP/1.1",
        "headers": _headers(txn.get("req_headers")),
        "queryString": [{"name": k, "value": v} for k, v in q],
        "cookies": [],
        "headersSize": -1,
        "bodySize": len(txn.get("req_body", "") or ""),
    }
    if txn.get("req_body"):
        req["postData"] = {"mimeType": "application/x-www-form-urlencoded",
                           "text": txn["req_body"]}
    resp_body = txn.get("resp_body", "") or ""
    resp = {
        "status": txn.get("status", 0),
        "statusText": "",
        "httpVersion": "HTTP/1.1",
        "headers": _headers(txn.get("resp_headers")),
        "cookies": [],
        "content": {"size": len(resp_body),
                    "mimeType": (txn.get("resp_headers") or {}).get(
                        "Content-Type", "text/plain"),
                    "text": resp_body},
        "redirectURL": (txn.get("resp_headers") or {}).get("Location", ""),
        "headersSize": -1,
        "bodySize": len(resp_body),
    }
    return {"startedDateTime": "1970-01-01T00:00:00.000Z",
            "time": txn.get("time_ms", 0),
            "request": req, "response": resp,
            "cache": {}, "timings": {"send": 0, "wait": txn.get("time_ms", 0),
                                     "receive": 0}}


def write(result, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = {
        "log": {
            "version": "1.2",
            "creator": {"name": "WebRecon", "version": "0.1"},
            "entries": [_entry(t) for t in getattr(result, "transactions", [])],
        }
    }
    path.write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
    return path

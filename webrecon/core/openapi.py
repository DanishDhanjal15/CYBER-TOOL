"""Seed the scanner from an OpenAPI / Swagger specification.

Reads a spec (local path or URL, JSON or YAML), extracts each operation's
query, path, and body parameters, and turns them into crawl targets so the
injection checks can fuzz real API endpoints even when there is nothing to
crawl (headless APIs).
"""
from __future__ import annotations

from pathlib import Path
from urllib.parse import urlencode

import yaml  # PyYAML also parses JSON

from webrecon.core.crawler import CrawlData, Form
from webrecon.core.http_client import HttpClient
from webrecon.core.target import Target


def load_spec(location: str, http: HttpClient) -> dict:
    if location.startswith(("http://", "https://")):
        resp = http.get(location, allow_redirects=True)
        if resp is None:
            raise ValueError(f"Could not fetch OpenAPI spec from {location}")
        return yaml.safe_load(resp.text) or {}
    return yaml.safe_load(Path(location).read_text(encoding="utf-8")) or {}


def _params_for(op: dict, shared: list) -> tuple[dict, list, dict]:
    """Return (query_params, path_params, body_fields) for one operation."""
    query: dict[str, str] = {}
    path_params: list[str] = []
    body: dict[str, str] = {}
    for p in list(shared) + list(op.get("parameters", []) or []):
        loc, name = p.get("in"), p.get("name")
        if not name:
            continue
        if loc == "query":
            query[name] = "1"
        elif loc == "path":
            path_params.append(name)
        elif loc == "body":  # Swagger 2 body schema
            for prop in ((p.get("schema") or {}).get("properties") or {}):
                body[prop] = "test"
    # OpenAPI 3 requestBody schema
    rb = (((op.get("requestBody") or {}).get("content") or {}))
    for _ctype, media in rb.items():
        for prop in ((media.get("schema") or {}).get("properties") or {}):
            body[prop] = "test"
    return query, path_params, body


def to_crawl(target: Target, spec: dict) -> CrawlData:
    data = CrawlData()
    base_path = spec.get("basePath", "")  # Swagger 2
    paths = spec.get("paths", {}) or {}

    for raw_path, item in paths.items():
        if not isinstance(item, dict):
            continue
        shared = item.get("parameters", []) or []
        for method, op in item.items():
            if method.lower() not in ("get", "post", "put", "delete", "patch"):
                continue
            if not isinstance(op, dict):
                continue
            query, path_params, body = _params_for(op, shared)

            # Fill path templates with a probe value.
            concrete = raw_path
            for name in path_params:
                concrete = concrete.replace("{" + name + "}", "1")
            url = target.url(base_path.rstrip("/") + concrete)

            if method.lower() == "get":
                if query:
                    full = url + ("&" if "?" in url else "?") + urlencode(query)
                    data.urls.append(full)
                    data.params[full] = list(query.keys())
                else:
                    data.urls.append(url)
            else:
                fields = dict(query)
                fields.update(body)
                if fields:
                    data.forms.append(Form(action=url, method="post",
                                           inputs=fields))
                else:
                    data.urls.append(url)
    return data


def merge(base: CrawlData, extra: CrawlData) -> CrawlData:
    seen = set(base.urls)
    for u in extra.urls:
        if u not in seen:
            base.urls.append(u)
            seen.add(u)
    for u, names in extra.params.items():
        base.params.setdefault(u, names)
    base.forms.extend(extra.forms)
    return base

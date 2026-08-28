"""Shared helpers for injection-style checks.

Provides a uniform way to enumerate injectable points (query parameters and
form fields) and to send a payload into a single point, returning the
response so a check can inspect it.
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

from webrecon.core.crawler import CrawlData, Form
from webrecon.core.http_client import HttpClient


@dataclass
class InjectionPoint:
    kind: str            # "query" or "form"
    url: str             # request URL (form action or param URL)
    method: str          # "get" or "post"
    param: str           # the parameter being fuzzed
    base_params: dict    # all params with baseline values


def enumerate_points(crawl: CrawlData, extra_urls: list[str] | None = None
                     ) -> list[InjectionPoint]:
    points: list[InjectionPoint] = []
    seen: set[tuple] = set()

    # Query-string parameters discovered while crawling.
    for url, names in crawl.params.items():
        parsed = urlparse(url)
        base = dict(parse_qsl(parsed.query))
        for name in names:
            key = ("query", url, name)
            if key in seen:
                continue
            seen.add(key)
            points.append(InjectionPoint("query", url, "get", name, base))

    # Form fields.
    for form in crawl.forms:
        for name in form.input_names():
            key = ("form", form.action, form.method, name)
            if key in seen:
                continue
            seen.add(key)
            points.append(InjectionPoint("form", form.action, form.method, name,
                                         dict(form.inputs)))
    return points


def send(http: HttpClient, point: InjectionPoint, payload: str,
         baseline: bool = False):
    """Send `payload` into `point.param`. If baseline, send a neutral value."""
    value = "1" if baseline else payload
    params = dict(point.base_params)
    params[point.param] = value

    if point.method == "post":
        return http.post(point.url, data=params)

    # GET: merge into the query string of the point URL.
    parsed = urlparse(point.url)
    merged = dict(parse_qsl(parsed.query))
    merged.update(params)
    new_query = urlencode(merged)
    new_url = urlunparse(parsed._replace(query=new_query))
    return http.get(new_url)


def build_poc(point: "InjectionPoint", payload: str) -> str:
    """Return a copy-paste curl command that reproduces the injection."""
    params = dict(point.base_params)
    params[point.param] = payload
    if point.method == "post":
        body = "&".join(f"{k}={v}" for k, v in params.items())
        return f"curl -i -X POST '{point.url}' --data '{body}'"
    parsed = urlparse(point.url)
    merged = dict(parse_qsl(parsed.query))
    merged.update(params)
    query = urlencode(merged)
    full = urlunparse(parsed._replace(query=query))
    return f"curl -i '{full}'"

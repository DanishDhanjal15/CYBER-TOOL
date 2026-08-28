"""A small, polite, same-host crawler.

Collects reachable URLs, discovers query parameters, and extracts HTML forms
(with their input fields) so injection checks have concrete places to test.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, parse_qs

from bs4 import BeautifulSoup

from .http_client import HttpClient
from .target import Target


@dataclass
class Form:
    action: str                      # absolute URL the form submits to
    method: str                      # "get" or "post"
    inputs: dict[str, str] = field(default_factory=dict)  # name -> default value

    def input_names(self) -> list[str]:
        return list(self.inputs.keys())


@dataclass
class CrawlData:
    urls: list[str] = field(default_factory=list)
    params: dict[str, list[str]] = field(default_factory=dict)  # url -> param names
    forms: list[Form] = field(default_factory=list)
    js_urls: list[str] = field(default_factory=list)  # <script src> discovered

    @property
    def url_count(self) -> int:
        return len(self.urls)

    @property
    def form_count(self) -> int:
        return len(self.forms)

    def param_targets(self) -> list[tuple[str, str]]:
        """Flat list of (url, param_name) pairs that carry a query parameter."""
        out: list[tuple[str, str]] = []
        for url, names in self.params.items():
            for name in names:
                out.append((url, name))
        return out


def _extract_forms(base_url: str, soup: BeautifulSoup) -> list[Form]:
    forms: list[Form] = []
    for tag in soup.find_all("form"):
        action = urljoin(base_url, tag.get("action") or base_url)
        method = (tag.get("method") or "get").lower()
        inputs: dict[str, str] = {}
        for inp in tag.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            inputs[name] = inp.get("value") or "test"
        forms.append(Form(action=action, method=method, inputs=inputs))
    return forms


def crawl(target: Target, http: HttpClient, *, depth: int = 2, max_urls: int = 200,
          progress=None) -> CrawlData:
    data = CrawlData()
    seen: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(target.url("/"), 0)])
    seen.add(target.url("/"))

    while queue and len(data.urls) < max_urls:
        url, level = queue.popleft()
        resp = http.get(url, allow_redirects=True)
        if resp is None:
            continue
        data.urls.append(url)
        if progress:
            progress(url, len(data.urls))

        # Record query parameters present on this URL.
        qs = parse_qs(urlparse(url).query)
        if qs:
            data.params[url] = list(qs.keys())

        ctype = resp.headers.get("Content-Type", "")
        if "html" not in ctype.lower():
            continue

        soup = BeautifulSoup(resp.text, "html.parser")
        data.forms.extend(_extract_forms(url, soup))

        # Collect external script sources for passive JS/secret analysis.
        for script in soup.find_all("script", src=True):
            js = urljoin(url, script["src"].split("#")[0])
            if js.startswith(("http://", "https://")) and js not in data.js_urls:
                data.js_urls.append(js)

        if level >= depth:
            continue

        for a in soup.find_all("a", href=True):
            link = urljoin(url, a["href"].split("#")[0])
            if not link.startswith(("http://", "https://")):
                continue
            if not target.in_scope(link):
                continue
            if link in seen:
                continue
            seen.add(link)
            queue.append((link, level + 1))
            # Also remember param-bearing links even if we won't crawl deeper.
            lqs = parse_qs(urlparse(link).query)
            if lqs:
                data.params.setdefault(link, list(lqs.keys()))

    return data

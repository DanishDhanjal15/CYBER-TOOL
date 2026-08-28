"""Technology fingerprinting from HTTP response headers and HTML metadata."""
from __future__ import annotations

from bs4 import BeautifulSoup

from webrecon.core.http_client import HttpClient
from webrecon.core.target import Target
from webrecon.data import load_lines


def gather(target: Target, http: HttpClient) -> dict:
    info: dict = {"technologies": {}, "headers": {}, "status": None}
    resp = http.get(target.url("/"), allow_redirects=True)
    if resp is None:
        info["error"] = "no response"
        return info

    info["status"] = resp.status_code
    info["headers"] = dict(resp.headers)

    for raw in load_lines("signatures/tech.txt"):
        header, key, label = raw.split("|", 2)
        value = resp.headers.get(header)
        if value:
            info["technologies"][label] = value

    # Meta generator tag often leaks CMS + version.
    if "html" in resp.headers.get("Content-Type", "").lower():
        soup = BeautifulSoup(resp.text, "html.parser")
        gen = soup.find("meta", attrs={"name": "generator"})
        if gen and gen.get("content"):
            info["technologies"]["Generator (meta)"] = gen["content"]
        if soup.title and soup.title.string:
            info["title"] = soup.title.string.strip()[:120]

    # Cookie names hint at the stack (PHPSESSID, JSESSIONID, etc.).
    cookies = resp.headers.get("Set-Cookie", "")
    if cookies:
        info["set_cookie_sample"] = cookies[:200]

    return info

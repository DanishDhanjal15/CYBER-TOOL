"""Historical URL discovery via the Wayback Machine CDX API.

Surfaces old/forgotten endpoints (admin panels, legacy APIs, param-bearing
URLs) that no longer appear in the live site but are still deployed. These
feed straight into the scanner's injection checks. Free, no key.
"""
from __future__ import annotations

from urllib.parse import urlparse

import requests

_CDX = ("https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json"
        "&fl=original&collapse=urlkey&filter=statuscode:200&limit={limit}")


def discover_urls(domain: str, scheme: str = "https", *, limit: int = 500,
                  timeout: int = 25) -> list[str]:
    """Return historical same-host URLs for `domain` (param-bearing first)."""
    try:
        r = requests.get(_CDX.format(domain=domain, limit=limit), timeout=timeout,
                         headers={"User-Agent": "WebRecon/0.1"})
        if r.status_code != 200:
            return []
        rows = r.json()
    except Exception:
        return []

    urls: list[str] = []
    seen: set[str] = set()
    for row in rows[1:]:                      # row 0 is the header
        original = row[0] if isinstance(row, list) and row else str(row)
        p = urlparse(original)
        if p.hostname and (p.hostname == domain or p.hostname.endswith("." + domain)):
            norm = original.split("#")[0]
            if norm not in seen:
                seen.add(norm)
                urls.append(norm)
    # Prioritise URLs that carry query parameters (best injection targets).
    urls.sort(key=lambda u: 0 if "?" in u else 1)
    return urls

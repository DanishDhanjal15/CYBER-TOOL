"""Certificate Transparency log subdomain enumeration (crt.sh).

Passive discovery of real subdomains from CT logs — far more complete than a
prefix wordlist, because it returns hostnames actually issued certificates.
Free, no API key. Falls back gracefully if crt.sh is slow/unreachable.
"""
from __future__ import annotations

import json
import re

import requests

_CRTSH = "https://crt.sh/?q=%25.{domain}&output=json"
_HOST_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9-_.]*[a-z0-9])?$", re.I)


def enumerate_subdomains(domain: str, *, timeout: int = 20) -> set[str]:
    """Return the set of subdomains of `domain` seen in CT logs."""
    found: set[str] = set()
    try:
        r = requests.get(_CRTSH.format(domain=domain), timeout=timeout,
                         headers={"User-Agent": "WebRecon/0.1"})
        if r.status_code != 200 or not r.text.strip():
            return found
        data = json.loads(r.text)
    except Exception:
        return found

    suffix = "." + domain.lower()
    for entry in data:
        names = str(entry.get("name_value", "")).splitlines()
        for name in names:
            name = name.strip().lower().lstrip("*.")
            if not name or "@" in name:
                continue
            if (name == domain.lower() or name.endswith(suffix)) and \
                    _HOST_RE.match(name):
                found.add(name)
    return found

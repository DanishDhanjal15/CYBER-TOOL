"""WHOIS/RDAP domain intel + ASN lookup — free, no API key.

RDAP (rdap.org) gives structured registrar/registrant/dates/nameservers.
Team Cymru's whois service maps an IP to its ASN + owning organisation.
"""
from __future__ import annotations

import socket

import requests


def rdap_domain(domain: str, *, timeout: int = 12) -> dict:
    out: dict = {}
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=timeout,
                         headers={"User-Agent": "WebRecon/0.1"})
        if r.status_code != 200:
            return out
        d = r.json()
    except Exception:
        return out

    out["handle"] = d.get("handle") or d.get("ldhName")
    events = {e.get("eventAction"): e.get("eventDate")
              for e in d.get("events", []) if isinstance(e, dict)}
    out["registered"] = events.get("registration")
    out["expires"] = events.get("expiration")
    out["last_changed"] = events.get("last changed")
    out["nameservers"] = [ns.get("ldhName") for ns in d.get("nameservers", [])
                          if isinstance(ns, dict) and ns.get("ldhName")]
    for ent in d.get("entities", []):
        roles = ent.get("roles", [])
        if "registrar" in roles:
            vcard = ent.get("vcardArray", [])
            if len(vcard) > 1:
                for item in vcard[1]:
                    if item and item[0] == "fn":
                        out["registrar"] = item[3]
    return out


def asn_lookup(ip: str, *, timeout: int = 8) -> dict:
    """Team Cymru whois: IP -> ASN, prefix, country, registry, org."""
    try:
        with socket.create_connection(("whois.cymru.com", 43), timeout=timeout) as s:
            s.sendall(f"begin\nverbose\n{ip}\nend\n".encode())
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
    except Exception:
        return {}
    lines = [ln for ln in data.decode("latin-1", "replace").splitlines()
             if ln and not ln.lower().startswith("bulk mode")]
    # Format: AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name
    for ln in lines[1:]:
        parts = [p.strip() for p in ln.split("|")]
        if len(parts) >= 7:
            return {"asn": parts[0], "prefix": parts[2], "country": parts[3],
                    "registry": parts[4], "org": parts[6]}
    return {}


def gather(target) -> dict:
    info: dict = {}
    if not target.is_ip:
        info["rdap"] = rdap_domain(target.host)
    ip = target.ip_addresses[0] if target.ip_addresses else None
    if ip:
        info["asn"] = asn_lookup(ip)
    return info

"""Version fingerprint -> known-CVE matching, enriched with EPSS / CISA KEV.

Detects product and library versions from response banners and JavaScript
bundles, then matches them against an offline CVE database. Each match is
prioritised with its EPSS score (probability of exploitation) and a KEV flag
(proven exploited in the wild) — the modern way to rank what to fix first.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

from webrecon.checks.base import Check
from webrecon.core.config import Config
from webrecon.core.crawler import CrawlData
from webrecon.core.http_client import HttpClient
from webrecon.core.target import Target
from webrecon.model.finding import Finding
from webrecon.model.severity import Severity

_DB = Path(__file__).resolve().parent.parent / "data" / "cve" / "known_cves.json"
_SEV = {s.value.lower(): s for s in Severity}
_MAX_JS = 20

# Banner "product/version" extraction, mapped to CVE-DB product keys.
_BANNER_RE = re.compile(r"([A-Za-z][A-Za-z\-]*)/(\d+\.\d+(?:\.\d+)?)")
_BANNER_MAP = {"nginx": "nginx", "apache": "apache", "httpd": "apache",
               "openssh": "openssh", "php": "php", "microsoft-iis": "iis",
               "iis": "iis", "coyote": "tomcat", "tomcat": "tomcat",
               "jetty": "jetty", "express": "express"}

# JS-library version fingerprints.
_JS_LIBS = {
    "jquery": re.compile(r"jQuery\s+(?:JavaScript Library\s+)?v?(\d+\.\d+\.\d+)", re.I),
    "bootstrap": re.compile(r"Bootstrap\s+v?(\d+\.\d+\.\d+)", re.I),
    "angular": re.compile(r"AngularJS\s+v?(\d+\.\d+\.\d+)", re.I),
    "lodash": re.compile(r"lodash[\s\S]{0,40}?VERSION\s*=\s*['\"](\d+\.\d+\.\d+)", re.I),
    "moment": re.compile(r"version\s*[:=]\s*['\"](\d+\.\d+\.\d+)['\"][\s\S]{0,40}?moment", re.I),
    "vue": re.compile(r"Vue(?:\.js)?\s+v?(\d+\.\d+\.\d+)", re.I),
}


@lru_cache(maxsize=None)
def _load_db(path: str | None) -> tuple:
    p = Path(path) if path else _DB
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return tuple(data.get("entries", []))
    except Exception:
        return tuple()


def _ver_tuple(v: str) -> tuple:
    parts = []
    for chunk in v.split("."):
        num = re.match(r"\d+", chunk)
        parts.append(int(num.group()) if num else 0)
    return tuple(parts)


def _lt(a: str, b: str) -> bool:
    ta, tb = _ver_tuple(a), _ver_tuple(b)
    length = max(len(ta), len(tb))
    ta += (0,) * (length - len(ta))
    tb += (0,) * (length - len(tb))
    return ta < tb


class CveCheck(Check):
    name = "cve"
    description = "Known-CVE matching from version banners/JS libs (+EPSS/KEV)."

    def run(self, target: Target, http: HttpClient, crawl: CrawlData,
            config: Config) -> list[Finding]:
        entries = _load_db(getattr(config, "cve_db", "") or None)
        if not entries:
            return []
        detected: dict[str, str] = {}   # product -> version (best/first)

        # 1) Response banners.
        resp = http.get(target.url("/"), allow_redirects=True)
        if resp is not None:
            for hdr in ("Server", "X-Powered-By", "X-AspNet-Version"):
                val = resp.headers.get(hdr, "")
                for prod, ver in _BANNER_RE.findall(val):
                    key = _BANNER_MAP.get(prod.lower())
                    if key:
                        detected.setdefault(key, ver)

        # 2) JavaScript library versions.
        for js in list(dict.fromkeys(crawl.js_urls))[:_MAX_JS]:
            r = http.get(js)
            if r is None or r.status_code != 200:
                continue
            text = r.text or ""
            for lib, rx in _JS_LIBS.items():
                m = rx.search(text)
                if m:
                    detected.setdefault(lib, m.group(1))

        # 3) Match detected versions against the CVE DB.
        findings: list[Finding] = []
        for entry in entries:
            prod = entry.get("product")
            ver = detected.get(prod)
            if not ver:
                continue
            if not _lt(ver, entry.get("version_lt", "0")):
                continue
            sev = _SEV.get(str(entry.get("severity", "medium")).lower(),
                           Severity.MEDIUM)
            kev = bool(entry.get("kev"))
            epss = entry.get("epss", 0.0)

            # Exploit intelligence (Exploit-DB / Metasploit / local searchsploit).
            from webrecon.recon.exploits import enrich
            exploit = enrich(entry, entry["cve"])
            tags = []
            if exploit["available"]:
                tags.append("EXPLOIT AVAILABLE")
            if kev:
                tags.append("KEV")
            tag_str = (" [" + ", ".join(tags) + "]") if tags else ""
            prio = ((", ".join(exploit["sources"]) + "; ") if exploit["sources"]
                    else "") + ("KEV — actively exploited; " if kev else "") + \
                   f"EPSS {epss:.0%}"

            # A weaponised + actively-exploited high-sev bug is emergency-grade.
            if exploit["available"] and kev and sev in (Severity.HIGH,
                                                        Severity.MEDIUM):
                sev = Severity.CRITICAL

            refs = [f"https://nvd.nist.gov/vuln/detail/{entry['cve']}",
                    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"]
            refs += exploit["refs"]

            findings.append(Finding(
                id=f"CVE-{entry['cve']}",
                title=f"{prod} {ver} — {entry['cve']}{tag_str}",
                severity=sev, owasp="A06:2021 - Vulnerable & Outdated Components",
                cwe="CWE-1035", cvss=float(entry.get("cvss", 0.0)),
                location=target.base_url,
                confidence="CONFIRMED" if exploit["available"] else "PROBABLE",
                description=f"Detected {prod} {ver}, affected by "
                            f"{entry['cve']}: {entry.get('description', '')}"
                            + (" A public exploit is available."
                               if exploit["available"] else ""),
                evidence=f"detected {prod}/{ver}; affected < "
                         f"{entry.get('version_lt')}; {prio}"
                         + (" | local: " + "; ".join(exploit["local_titles"])
                            if exploit.get("local_titles") else ""),
                impact="Exploitation of a known CVE in an outdated component"
                       + (" — a working public exploit exists, so this is "
                          "low-effort for an attacker." if exploit["available"]
                          else ".")
                       + (" On CISA KEV (attacks ongoing)." if kev else ""),
                remediation=f"Upgrade {prod} to {entry.get('version_lt')} or later.",
                poc=(f"searchsploit --cve {entry['cve']}   # "
                     + (", ".join(exploit["sources"]) if exploit["sources"]
                        else "check Exploit-DB")),
                references=refs))
        return findings

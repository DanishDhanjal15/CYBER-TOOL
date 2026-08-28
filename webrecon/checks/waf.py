"""WAF / CDN detection — fingerprint the edge protecting the site."""
from __future__ import annotations

from webrecon.checks.base import Check
from webrecon.core.config import Config
from webrecon.core.crawler import CrawlData
from webrecon.core.http_client import HttpClient
from webrecon.core.target import Target
from webrecon.model.finding import Finding
from webrecon.model.severity import Severity

# signature -> product (checked against headers + cookies + body)
_SIGS = {
    "cloudflare": "Cloudflare", "cf-ray": "Cloudflare", "__cfduid": "Cloudflare",
    "x-sucuri": "Sucuri", "sucuri": "Sucuri",
    "akamai": "Akamai", "akamaighost": "Akamai",
    "incapsula": "Imperva Incapsula", "x-iinfo": "Imperva Incapsula",
    "x-cdn": "Generic CDN", "fastly": "Fastly", "x-served-by": "Fastly/Varnish",
    "aws": "AWS CloudFront/ALB", "x-amz-cf-id": "AWS CloudFront",
    "x-azure-ref": "Azure Front Door", "barracuda": "Barracuda",
    "f5": "F5 BIG-IP", "x-waf": "Generic WAF", "mod_security": "ModSecurity",
    "awselb": "AWS ELB",
}
# A blocking response to a malicious probe strongly implies an active WAF.
_PROBE = "?wr=<script>alert(1)</script>' OR 1=1--"


class WafCdnCheck(Check):
    name = "waf"
    description = "WAF / CDN detection (edge fingerprint + block behaviour)."

    def run(self, target: Target, http: HttpClient, crawl: CrawlData,
            config: Config) -> list[Finding]:
        resp = http.get(target.url("/"), allow_redirects=True)
        if resp is None:
            return []
        blob = " ".join(f"{k}: {v}" for k, v in resp.headers.items()).lower()
        blob += " " + resp.headers.get("Set-Cookie", "").lower()
        detected = sorted({name for sig, name in _SIGS.items() if sig in blob})

        # Active probe: does a malicious request get blocked (403/406/429/501)?
        blocked = False
        probe = http.get(target.url("/") + _PROBE, allow_redirects=False)
        if probe is not None and probe.status_code in (403, 406, 429, 501, 999):
            blocked = True

        if not detected and not blocked:
            return []
        name = ", ".join(detected) if detected else "Unknown WAF"
        return [Finding(
            id="WAF-001", title=f"WAF / CDN detected: {name}",
            severity=Severity.INFO, owasp="Reconnaissance", cwe="",
            cvss=0.0, location=target.base_url, confidence="CONFIRMED",
            description=f"The site sits behind {name}"
                        + (" and blocked a malicious probe." if blocked else "."),
            evidence=(f"signatures: {name}" if detected else "")
                     + ("; malicious probe blocked" if blocked else ""),
            impact="Informational — payloads may need WAF-evasion; consider "
                   "origin-IP discovery to bypass the edge.",
            remediation="No action (positive control). Ensure origin isn't "
                        "directly reachable, bypassing the WAF.",
            references=[])]

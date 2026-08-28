"""Subdomain enumeration + dangling-CNAME takeover detection.

Probes a curated prefix list (offensive-osint §16.24), resolves each, and for
any whose CNAME points to a third-party service, checks the HTTP response for
that provider's "unclaimed resource" signature (offensive-osint §16.12).
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import dns.resolver
    _HAS_DNS = True
except Exception:  # pragma: no cover
    _HAS_DNS = False

from webrecon.core.http_client import HttpClient
from webrecon.core.target import Target
from webrecon.model.finding import Finding
from webrecon.model.severity import Severity


_PREFIXES = [
    "www", "mail", "webmail", "api", "app", "apps", "m", "mobile", "portal",
    "login", "sso", "admin", "dev", "test", "staging", "stg", "qa", "uat",
    "sandbox", "preprod", "demo", "beta", "old", "legacy", "cdn", "static",
    "assets", "media", "img", "files", "downloads", "docs", "wiki", "blog",
    "shop", "store", "status", "support", "help", "vpn", "git", "jenkins",
    "grafana", "kibana", "ci", "internal", "intranet", "dashboard",
]

# CNAME substring -> (provider, takeover signature substring)
_FINGERPRINTS = {
    "github.io": ("GitHub Pages", "there isn't a github pages site here"),
    "herokuapp.com": ("Heroku", "no such app"),
    "herokudns.com": ("Heroku", "no such app"),
    "s3.amazonaws.com": ("AWS S3", "nosuchbucket"),
    "s3-website": ("AWS S3", "nosuchbucket"),
    "cloudfront.net": ("AWS CloudFront", "bad request"),
    "azurewebsites.net": ("Azure", "404 web site not found"),
    "cloudapp.net": ("Azure", "404 web site not found"),
    "trafficmanager.net": ("Azure", "404 web site not found"),
    "blob.core.windows.net": ("Azure Blob", "the specified blob does not exist"),
    "myshopify.com": ("Shopify", "sorry, this shop is currently unavailable"),
    "squarespace.com": ("Squarespace", "no such account"),
    "wordpress.com": ("WordPress", "do you want to register"),
    "pantheonsite.io": ("Pantheon", "the gods are wise"),
    "surge.sh": ("Surge.sh", "project not found"),
    "bitbucket.io": ("Bitbucket", "repository not found"),
    "fastly.net": ("Fastly", "fastly error: unknown domain"),
    "ghost.io": ("Ghost", "domain error"),
    "helpscoutdocs.com": ("HelpScout", "no settings were found"),
    "zendesk.com": ("Zendesk", "help center closed"),
    "readthedocs.io": ("ReadTheDocs", "unknown domain"),
    "netlify.app": ("Netlify", "not found - request id"),
    "webflow.io": ("Webflow", "the page you are looking for doesn't exist"),
    "ngrok.io": ("Ngrok", "tunnel not found"),
}


def _resolve_cname(host: str) -> str | None:
    if not _HAS_DNS:
        return None
    try:
        answers = dns.resolver.resolve(host, "CNAME")
        return str(answers[0].target).rstrip(".").lower()
    except Exception:
        return None


def _resolves(host: str) -> bool:
    if not _HAS_DNS:
        return False
    for rtype in ("A", "AAAA", "CNAME"):
        try:
            dns.resolver.resolve(host, rtype)
            return True
        except Exception:
            continue
    return False


def scan(target: Target, http: HttpClient, *, threads: int = 20
         ) -> tuple[dict, list[Finding]]:
    info: dict = {"tested": 0, "resolved": [], "cnames": {}}
    findings: list[Finding] = []
    if target.is_ip or not _HAS_DNS:
        info["note"] = "subdomain scan skipped (IP target or dnspython missing)"
        return info, findings

    apex = target.host
    hosts = [f"{p}.{apex}" for p in _PREFIXES]
    info["tested"] = len(hosts)

    def probe(host: str):
        if not _resolves(host):
            return None
        cname = _resolve_cname(host)
        return host, cname

    resolved: list[tuple[str, str | None]] = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        for fut in as_completed([pool.submit(probe, h) for h in hosts]):
            r = fut.result()
            if r:
                resolved.append(r)

    for host, cname in resolved:
        info["resolved"].append(host)
        if cname:
            info["cnames"][host] = cname
            for needle, (provider, signature) in _FINGERPRINTS.items():
                if needle in cname:
                    findings.append(_maybe_takeover(http, host, cname, provider,
                                                    signature))
                    break
    findings = [f for f in findings if f is not None]
    return info, findings


def _maybe_takeover(http: HttpClient, host: str, cname: str, provider: str,
                    signature: str):
    for scheme in ("https", "http"):
        resp = http.get(f"{scheme}://{host}/", allow_redirects=True)
        if resp is None:
            continue
        if signature in (resp.text or "").lower():
            return Finding(
                id="TAKEOVER-001",
                title=f"Subdomain takeover possible: {host} ({provider})",
                severity=Severity.HIGH,
                owasp="A05:2021 - Security Misconfiguration", cwe="CWE-350",
                cvss=8.1, location=host, confidence="PROBABLE",
                description=f"{host} has a dangling CNAME to unclaimed {provider} "
                            f"infrastructure ({cname}).",
                evidence=f"CNAME -> {cname}; response contains "
                         f"'{signature}'",
                impact="An attacker can claim the resource and serve content from a "
                       "trusted subdomain (phishing, cookie theft, token capture).",
                remediation=f"Remove the dangling DNS record or re-claim the "
                            f"{provider} resource.",
                poc=f"dig CNAME {host}  # -> {cname}",
                references=["https://cwe.mitre.org/data/definitions/350.html"])
    return None

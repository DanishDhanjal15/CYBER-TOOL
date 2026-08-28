"""Rate-limiting detection + per-endpoint algorithm recommendation.

Sends a short, polite burst of requests to representative endpoints (homepage,
login forms, a couple of API/param URLs) and checks whether the server pushes
back — HTTP 429, RateLimit/Retry-After headers, or "too many requests" bodies.

For each endpoint it reports whether rate limiting is present, and — most
usefully — recommends the *right algorithm for that endpoint type* (sliding
window for auth/writes, token bucket for read APIs, leaky bucket for expensive
search/export) and where to enforce it.
"""
from __future__ import annotations

from webrecon.analysis.ratelimit_advisor import recommend
from webrecon.checks.base import Check
from webrecon.core.config import Config
from webrecon.core.crawler import CrawlData
from webrecon.core.http_client import HttpClient
from webrecon.core.target import Target
from webrecon.model.finding import Finding
from webrecon.model.severity import Severity

_RL_HEADERS = ("ratelimit-limit", "ratelimit-remaining", "ratelimit-reset",
               "x-ratelimit-limit", "x-ratelimit-remaining", "x-rate-limit-limit",
               "retry-after")
_BODY_MARKERS = ("too many requests", "rate limit", "rate-limited", "slow down",
                 "try again later", "quota exceeded", "error 1015")
# Severity of a MISSING limiter, by endpoint type.
_MISSING_SEV = {"auth": Severity.HIGH, "write": Severity.MEDIUM,
                "api": Severity.MEDIUM, "search": Severity.MEDIUM,
                "upload": Severity.MEDIUM, "general": Severity.LOW}


class RateLimitCheck(Check):
    name = "ratelimit"
    description = "Rate-limiting detection + per-endpoint algorithm advice."

    def run(self, target: Target, http: HttpClient, crawl: CrawlData,
            config: Config) -> list[Finding]:
        burst = int(getattr(config, "rl_burst", 20) or 20)
        findings: list[Finding] = []
        tested: set[str] = set()

        # 1) Homepage (general) + a diverse sample of param URLs (prefer the
        #    interesting types — api/search/write/auth — over generic ones).
        from webrecon.analysis.ratelimit_advisor import classify
        endpoints: list[tuple[str, str, dict | None]] = [(target.url("/"), "get", None)]
        param_urls = sorted(crawl.params.keys(),
                            key=lambda u: 0 if classify(u) != "general" else 1)
        for url in param_urls[:5]:
            endpoints.append((url, "get", None))
        # 2) Login/auth forms (POST) — most important to rate-limit.
        for form in crawl.forms:
            names = " ".join(form.input_names()).lower()
            if any(k in names for k in ("pass", "user", "email", "login")):
                data = {n: "wr_rltest" for n in form.input_names()}
                endpoints.append((form.action, "post", data))

        for url, method, data in endpoints:
            if url in tested:
                continue
            tested.add(url)
            result = self._probe(http, method, url, data, burst)
            findings.append(self._finding(url, result, burst))
        return findings

    def _probe(self, http, method, url, data, burst) -> dict:
        limited = False
        mechanism = None
        headers_seen: dict[str, str] = {}
        statuses: list[int] = []
        for i in range(burst):
            if method == "post":
                resp = http.post(url, data=data or {}, allow_redirects=False)
            else:
                resp = http.get(url, allow_redirects=False)
            if resp is None:
                continue
            statuses.append(resp.status_code)
            lowered = {k.lower(): v for k, v in resp.headers.items()}
            for h in _RL_HEADERS:
                if h in lowered:
                    headers_seen[h] = lowered[h]
            body = (resp.text or "")[:400].lower()
            if resp.status_code == 429:
                limited, mechanism = True, "HTTP 429 responses"
                break
            if any(m in body for m in _BODY_MARKERS):
                limited, mechanism = True, "rate-limit response body"
                break
        if not limited and headers_seen:
            # Documented limits present even without a 429 in this short burst.
            limited = True
            if "retry-after" in headers_seen:
                mechanism = "Retry-After header"
            else:
                mechanism = "RateLimit-* headers"
        return {"limited": limited, "mechanism": mechanism or "none",
                "headers": headers_seen, "requests": len(statuses)}

    def _finding(self, url, result, burst) -> Finding:
        rec = recommend(url)
        etype = rec["endpoint_type"]
        advice = (f"Recommended for this {etype} endpoint: {rec['algo']}. "
                  f"{rec['why']} Example: {rec['example']} "
                  f"Enforce at: {rec['where']}")

        if result["limited"]:
            hdrs = ", ".join(f"{k}={v}" for k, v in result["headers"].items())
            return Finding(
                id="RATELIMIT-OK-001",
                title=f"Rate limiting active on {etype} endpoint",
                severity=Severity.INFO,
                owasp="A04:2021 - Insecure Design", cwe="",
                cvss=0.0, location=url, confidence="CONFIRMED",
                description=f"The endpoint pushed back during a {burst}-request "
                            f"burst ({result['mechanism']}) — a rate-limiting "
                            "control is present.",
                evidence=f"mechanism: {result['mechanism']}"
                         + (f"; headers: {hdrs}" if hdrs else ""),
                impact="Positive control. Verify the limit is tight enough for "
                       "this endpoint type.",
                remediation=advice,
                references=["https://datatracker.ietf.org/doc/draft-ietf-httpapi-"
                            "ratelimit-headers/"])

        sev = _MISSING_SEV.get(etype, Severity.LOW)
        return Finding(
            id="RATELIMIT-001",
            title=f"No rate limiting on {etype} endpoint",
            severity=sev, owasp="A04:2021 - Insecure Design", cwe="CWE-770",
            cvss=7.5 if sev == Severity.HIGH else (5.3 if sev == Severity.MEDIUM
                                                   else 3.1),
            location=url, confidence="PROBABLE",
            description=f"A burst of {burst} requests ran with no 429, "
                        "RateLimit headers, or throttling response — the endpoint "
                        "appears to have no rate limiting.",
            evidence=f"{burst} requests, no throttling observed; "
                     f"statuses were not 429",
            impact=("Brute-force / credential-stuffing at scale."
                    if etype == "auth" else
                    "Resource abuse, scraping, and denial-of-service."),
            remediation=advice,
            poc=f"Send {burst}+ rapid requests to {url} — none are throttled.",
            references=["https://cwe.mitre.org/data/definitions/770.html"])

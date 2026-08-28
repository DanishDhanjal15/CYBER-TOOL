"""Recommend the right rate-limiting algorithm per endpoint type + where to put it.

Given a URL, classify what kind of endpoint it is, then return the algorithm
that fits (sliding window, token bucket, leaky bucket, fixed window), the
rationale, a concrete example limit, and where in the stack to enforce it.
"""
from __future__ import annotations

import re

# order matters: first match wins
_TYPES = [
    ("auth", re.compile(r"(login|signin|sign-in|auth|session|password|reset|"
                        r"forgot|otp|verify|2fa|mfa|token|oauth|register|signup)", re.I)),
    ("search", re.compile(r"(search|query|report|export|download|filter|lookup|"
                          r"suggest|autocomplete)", re.I)),
    ("upload", re.compile(r"(upload|import|attachment|avatar|/media/|/files?/|"
                          r"\bfile\b)", re.I)),
    ("write", re.compile(r"(create|update|delete|edit|post|comment|submit|order|"
                         r"checkout|payment|transfer)", re.I)),
    ("api", re.compile(r"(/api/|/graphql|/v\d+/|/rest/|/gql)", re.I)),
]

_RECS = {
    "auth": {
        "algo": "Sliding Window Counter (per-account) + per-IP limit + exponential backoff",
        "why": "Login/auth must resist credential stuffing. A sliding window "
               "avoids the double-burst that fixed windows allow at window edges; "
               "combine per-account lockout with a per-IP cap and back off "
               "exponentially after each failure.",
        "example": "5 failed attempts / 15 min per account; 20 / min per IP; "
                   "lock 15 min after 5 fails; add CAPTCHA + MFA.",
        "where": "App auth middleware (per-account state) + edge/WAF (per-IP).",
    },
    "search": {
        "algo": "Leaky Bucket (or low-refill Token Bucket)",
        "why": "Search/report/export are expensive on the backend. A leaky "
               "bucket drains at a constant rate so a client can't overwhelm the "
               "database with spikes.",
        "example": "10 req/min steady drain, small burst of 3.",
        "where": "API gateway or service layer, keyed by user/API-key.",
    },
    "upload": {
        "algo": "Token Bucket with a low limit + per-user quota",
        "why": "Uploads consume bandwidth/storage; a token bucket allows the "
               "occasional legitimate burst while a daily quota caps abuse.",
        "example": "5 uploads/min burst 2; 100/day per user.",
        "where": "Upload service + storage-quota check.",
    },
    "write": {
        "algo": "Sliding Window Counter (stricter limits than reads)",
        "why": "State-changing writes deserve tighter, accurate limiting to stop "
               "spam and abuse without the edge-burst of fixed windows.",
        "example": "30 writes/min per user; lower for payment/order endpoints.",
        "where": "App middleware keyed by authenticated user.",
    },
    "api": {
        "algo": "Token Bucket (per API key / per IP)",
        "why": "Read APIs benefit from bursts for good UX; a token bucket allows "
               "short bursts up to the bucket size and refills smoothly.",
        "example": "100 req/min, burst 20, per API key.",
        "where": "API gateway (Kong/Envoy/nginx) or a shared Redis limiter.",
    },
    "general": {
        "algo": "Sliding Window Counter (per IP)",
        "why": "A good default: accurate, cheap, and free of the window-edge "
               "double-burst that plain fixed windows suffer.",
        "example": "60 req/min per IP.",
        "where": "Edge / reverse proxy (nginx limit_req, Cloudflare) or CDN.",
    },
}


def classify(url: str) -> str:
    for name, rx in _TYPES:
        if rx.search(url or ""):
            return name
    return "general"


def recommend(url: str) -> dict:
    etype = classify(url)
    rec = dict(_RECS.get(etype, _RECS["general"]))
    rec["endpoint_type"] = etype
    return rec

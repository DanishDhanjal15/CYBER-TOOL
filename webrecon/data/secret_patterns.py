"""Secret-detection regex catalog (subset of the offensive-osint §17 catalog).

Ordered most-specific first so typed patterns win over generic ones. Each
entry: (name, severity, cwe, regex). Severity strings map to model.Severity.
"""
from __future__ import annotations

import re

from webrecon.model.severity import Severity

# (name, severity, cwe, pattern)
_RAW = [
    ("AWS Access Key", Severity.CRITICAL, "CWE-798", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("AWS Secret Key", Severity.CRITICAL, "CWE-798",
     r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key['\"\s:=]+([A-Za-z0-9/+=]{40})"),
    ("GCP Service Account", Severity.CRITICAL, "CWE-798",
     r'"type"\s*:\s*"service_account"'),
    ("Google API Key", Severity.HIGH, "CWE-798", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("GitHub Classic PAT", Severity.CRITICAL, "CWE-798", r"\bghp_[A-Za-z0-9]{36}\b"),
    ("GitHub Fine-grained PAT", Severity.CRITICAL, "CWE-798",
     r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
    ("GitHub OAuth Token", Severity.HIGH, "CWE-798", r"\bgho_[A-Za-z0-9]{36}\b"),
    ("Stripe Live Key", Severity.CRITICAL, "CWE-798", r"\bsk_live_[0-9A-Za-z]{24,}\b"),
    ("Stripe Test Key", Severity.LOW, "CWE-798", r"\bsk_test_[0-9A-Za-z]{24,}\b"),
    ("Slack Token", Severity.HIGH, "CWE-798", r"\bxox[abpors]-[0-9A-Za-z\-]{10,48}\b"),
    ("Slack Webhook", Severity.MEDIUM, "CWE-798",
     r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    ("SendGrid Key", Severity.HIGH, "CWE-798",
     r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
    ("Twilio API Key", Severity.HIGH, "CWE-798", r"\bSK[0-9a-fA-F]{32}\b"),
    ("Anthropic API Key", Severity.CRITICAL, "CWE-798",
     r"\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_\-]{20,}\b"),
    ("OpenAI Project Key", Severity.CRITICAL, "CWE-798",
     r"\bsk-proj-[A-Za-z0-9_\-]{20,}\b"),
    ("OpenAI Key", Severity.CRITICAL, "CWE-798",
     r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b"),
    ("HuggingFace Token", Severity.HIGH, "CWE-798", r"\bhf_[A-Za-z0-9]{30,}\b"),
    ("DigitalOcean Token", Severity.HIGH, "CWE-798", r"\bdop_v1_[a-f0-9]{64}\b"),
    ("npm Token", Severity.HIGH, "CWE-798", r"\bnpm_[A-Za-z0-9]{36}\b"),
    ("Docker Hub PAT", Severity.HIGH, "CWE-798", r"\bdckr_pat_[A-Za-z0-9_\-]{27,}\b"),
    ("Atlassian API Token", Severity.HIGH, "CWE-798",
     r"\bATATT3xFfGF0[A-Za-z0-9_\-]{180,}\b"),
    ("Sentry DSN", Severity.LOW, "CWE-798",
     r"https://[a-f0-9]+@o[0-9]+\.ingest\.sentry\.io/[0-9]+"),
    ("Discord Bot Token", Severity.HIGH, "CWE-798",
     r"\b[MN][A-Za-z\d]{23}\.[\w\-]{6}\.[\w\-]{27}\b"),
    ("Telegram Bot Token", Severity.HIGH, "CWE-798",
     r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b"),
    ("RSA Private Key", Severity.CRITICAL, "CWE-321",
     r"-----BEGIN RSA PRIVATE KEY-----"),
    ("EC Private Key", Severity.CRITICAL, "CWE-321", r"-----BEGIN EC PRIVATE KEY-----"),
    ("OpenSSH Private Key", Severity.CRITICAL, "CWE-321",
     r"-----BEGIN OPENSSH PRIVATE KEY-----"),
    ("Generic Private Key", Severity.CRITICAL, "CWE-321",
     r"-----BEGIN (DSA |PGP |)PRIVATE KEY-----"),
    ("Basic Auth in URL", Severity.MEDIUM, "CWE-522",
     r"https?://[^/\s:@]+:[^/\s:@]+@[^/\s]+"),
    ("Firebase URL", Severity.LOW, "CWE-200",
     r"\bhttps?://[a-z0-9\-]+\.firebaseio\.com\b"),
    ("Generic API Key", Severity.MEDIUM, "CWE-798",
     r"(?i)(?:api[_\-]?key|apikey|api_secret|access_token|secret[_\-]?token)"
     r"['\"\s:=]+[\"']([A-Za-z0-9+/=_\-]{24,})[\"']"),
]

# Internal-host leakage (offensive-osint §16.11)
_HOST_LEAK = [
    ("RFC1918 internal IP",
     r"\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
     r"|192\.168\.\d{1,3}\.\d{1,3})\b"),
    ("Internal DNS name",
     r"\b[A-Za-z0-9][A-Za-z0-9\-]{0,62}\."
     r"(?:internal|corp|lan|intranet|local|prod|staging|dev|qa|test)\b"),
    ("Kubernetes service DNS", r"\b[A-Za-z0-9\-]+\.[A-Za-z0-9\-]+\.svc(?:\.cluster\.local)?\b"),
]

SECRET_PATTERNS = [(n, s, c, re.compile(p)) for (n, s, c, p) in _RAW]
HOST_LEAK_PATTERNS = [(n, re.compile(p)) for (n, p) in _HOST_LEAK]

# JS files worth probing directly even if not linked (offensive-osint §16.9)
JS_GUESS_PATHS = [
    "/main.js", "/app.js", "/bundle.js", "/runtime.js", "/vendor.js",
    "/static/js/main.js", "/static/js/bundle.js", "/assets/index.js",
    "/_next/static/_buildManifest.js",
]

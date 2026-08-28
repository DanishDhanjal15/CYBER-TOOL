"""Auto-remediation — turn findings into ready-to-apply fixes.

WebRecon doesn't just find issues; for the deterministic ones (missing security
headers, insecure cookies, weak CSP, wildcard CORS, directory listing, unsafe
HTTP methods, missing security.txt) it emits the exact config for your stack
(nginx / Apache / Express / Flask / Django). Paste it in — or --apply it.
"""
from __future__ import annotations

STACKS = ("nginx", "apache", "express", "flask", "django", "generic")

# Security-header value recommendations (header -> value).
_HDR = {
    "content-security-policy": "default-src 'self'",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "geolocation=(), microphone=(), camera=()",
}
# Map a finding title fragment -> canonical header name.
_TITLE_HDR = {
    "content-security-policy": "content-security-policy",
    "strict-transport-security": "strict-transport-security",
    "x-frame-options": "x-frame-options",
    "x-content-type-options": "x-content-type-options",
    "referrer-policy": "referrer-policy",
    "permissions-policy": "permissions-policy",
}


def detect_stack(result) -> str:
    server = ((result.recon.get("fingerprint", {}) or {})
              .get("headers", {}) or {}).get("Server", "").lower()
    powered = ((result.recon.get("fingerprint", {}) or {})
               .get("headers", {}) or {}).get("X-Powered-By", "").lower()
    blob = server + " " + powered
    if "nginx" in blob:
        return "nginx"
    if "apache" in blob:
        return "apache"
    if "express" in blob or "node" in blob:
        return "express"
    if "gunicorn" in blob or "werkzeug" in blob or "flask" in blob:
        return "flask"
    if "django" in blob or "wsgi" in blob:
        return "django"
    return "generic"


def _header_fix(header: str, stack: str) -> str:
    val = _HDR[header]
    canon = "-".join(w.capitalize() for w in header.split("-"))
    if stack == "nginx":
        return f'add_header {canon} "{val}" always;'
    if stack == "apache":
        return f'Header always set {canon} "{val}"'
    if stack == "express":
        return f'res.setHeader("{canon}", "{val}");'
    if stack == "flask":
        return f'resp.headers["{canon}"] = "{val}"'
    if stack == "django":
        _dj = {"strict-transport-security": "SECURE_HSTS_SECONDS = 31536000",
               "x-content-type-options": "SECURE_CONTENT_TYPE_NOSNIFF = True",
               "x-frame-options": 'X_FRAME_OPTIONS = "DENY"'}
        return _dj.get(header, f'# set {canon}: {val} (via middleware / django-csp)')
    return f'{canon}: {val}'


def _cookie_fix(stack: str) -> str:
    return {
        "nginx": "# set cookie flags in your app; at the edge you can rewrite:\n"
                 'proxy_cookie_flags ~ secure httponly samesite=strict;',
        "apache": 'Header always edit Set-Cookie ^(.*)$ "$1; HttpOnly; Secure; '
                  'SameSite=Strict"',
        "express": 'res.cookie(name, val, { httpOnly: true, secure: true, '
                   'sameSite: "strict" });',
        "flask": 'resp.set_cookie(name, val, httponly=True, secure=True, '
                 'samesite="Strict")',
        "django": "SESSION_COOKIE_HTTPONLY = True\nSESSION_COOKIE_SECURE = True\n"
                  'SESSION_COOKIE_SAMESITE = "Strict"',
        "generic": "Set cookies with: HttpOnly; Secure; SameSite=Strict",
    }[stack]


def _cors_fix(stack: str) -> str:
    return ("# Never use '*' with credentials. Allow an explicit origin list:\n"
            + {"nginx": 'add_header Access-Control-Allow-Origin "https://your-app.com" always;',
               "apache": 'Header always set Access-Control-Allow-Origin "https://your-app.com"',
               "express": 'cors({ origin: ["https://your-app.com"], credentials: true })',
               "flask": 'CORS(app, origins=["https://your-app.com"])',
               "django": 'CORS_ALLOWED_ORIGINS = ["https://your-app.com"]',
               "generic": 'Access-Control-Allow-Origin: https://your-app.com'}[stack])


def _dirlisting_fix(stack: str) -> str:
    return {"nginx": "autoindex off;", "apache": "Options -Indexes",
            "express": "// don't use express.static with a browsable index",
            "flask": "# don't serve directories; disable auto-index",
            "django": "# never expose MEDIA/STATIC dirs with listing",
            "generic": "Disable directory auto-indexing on the web server."}[stack]


def generate(result, stack: str = "") -> tuple[str, int]:
    """Return (config_text, num_fixes) for the fixable findings in `result`."""
    stack = stack or detect_stack(result)
    lines: list[str] = [f"# WebRecon auto-remediation — stack: {stack}",
                        f"# Target: {result.target}", ""]
    seen: set[str] = set()
    count = 0

    def add(title, snippet):
        nonlocal count
        if snippet in seen:
            return
        seen.add(snippet)
        lines.append(f"# Fix: {title}")
        lines.append(snippet)
        lines.append("")
        count += 1

    for f in result.sorted_findings():
        title = f.title.lower()
        rk = f.rule_key()
        if rk.startswith("SEC-HEADERS"):
            for frag, hdr in _TITLE_HDR.items():
                if frag in title:
                    add(f.title, _header_fix(hdr, stack))
                    break
        elif rk.startswith("COOKIE"):
            add("Insecure cookie flags", _cookie_fix(stack))
        elif rk.startswith("CORS"):
            add("Permissive CORS", _cors_fix(stack))
        elif rk.startswith("DIRLIST"):
            add("Directory listing enabled", _dirlisting_fix(stack))
        elif rk.startswith("CSP"):
            add("Weak Content-Security-Policy",
                _header_fix("content-security-policy", stack))
        elif rk.startswith("SECTXT"):
            add("Missing security.txt",
                "# Create /.well-known/security.txt:\n"
                "Contact: mailto:security@your-app.com\n"
                "Expires: 2027-01-01T00:00:00Z")
        elif rk.startswith("METHOD"):
            add("Dangerous HTTP method enabled",
                {"nginx": 'if ($request_method !~ ^(GET|POST|HEAD)$){ return 405; }',
                 "apache": '<LimitExcept GET POST HEAD>\n  Require all denied\n</LimitExcept>',
                 "generic": "Disable TRACE/PUT/DELETE unless required."}.get(
                    stack, "Disable TRACE/PUT/DELETE unless required."))

    if count == 0:
        lines.append("# No auto-fixable findings — nothing to remediate. 🎉")
    return "\n".join(lines), count

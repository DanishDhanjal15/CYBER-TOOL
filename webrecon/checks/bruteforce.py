"""Online login brute-force / weak-credential audit (OPT-IN, authorized only).

Given a login form, this tries a wordlist of common/weak passwords (bundled
top-100, or rockyou / any list via --wordlist) against one or more usernames
and reports any account that accepts a weak password — so the owner can change
it. It also reports the *absence* of brute-force protection (no lockout / rate
limiting), which is itself a finding.

Safety rails:
  * Never runs by default — only when explicitly opted in (--bruteforce or
    --checks bruteforce), on top of the standard --authorize gate.
  * Hard cap on total attempts (--max-attempts, default 200) so it can't hammer
    an account into oblivion or act as a DoS. rockyou has millions of entries;
    realistic online guessing tests the top-N only.
  * Stops immediately if the target signals account lockout.
"""
from __future__ import annotations

from pathlib import Path

from webrecon.checks.base import Check
from webrecon.core.config import Config
from webrecon.core.crawler import CrawlData, Form
from webrecon.core.http_client import HttpClient
from webrecon.core.target import Target
from webrecon.data import load_lines
from webrecon.model.finding import Finding
from webrecon.model.severity import Severity

_PW_FIELDS = ("password", "passwd", "pass", "pwd", "pw")
_USER_FIELDS = ("username", "user", "email", "login", "userid", "uid", "user_name")
_DEFAULT_USERS = ("admin", "administrator", "root", "test", "user")
_FAIL_MARKERS = ("invalid", "incorrect", "wrong", "failed", "denied",
                 "try again", "not found", "does not exist", "bad credentials")
_LOCKOUT_MARKERS = ("locked", "too many", "temporarily", "rate limit",
                    "try again later", "account disabled", "captcha")


class BruteForceCheck(Check):
    name = "bruteforce"
    description = "Weak-credential / login brute-force audit (opt-in, authorized)."

    def run(self, target: Target, http: HttpClient, crawl: CrawlData,
            config: Config) -> list[Finding]:
        # Opt-in guard: only run when explicitly requested.
        if not (getattr(config, "bruteforce", False)
                or (config.checks and "bruteforce" in config.checks)):
            return []

        forms = [f for f in crawl.forms if self._is_login_form(f)]
        if not forms:
            return []

        passwords = self._load_passwords(config)
        users = ([u.strip() for u in str(getattr(config, "username", "") or "").split(",")
                  if u.strip()] or list(_DEFAULT_USERS))
        max_attempts = int(getattr(config, "max_attempts", 200) or 200)

        findings: list[Finding] = []
        for form in forms:
            findings.extend(self._attack_form(target, http, form, users,
                                              passwords, max_attempts))
        return findings

    # -- helpers ----------------------------------------------------------
    def _is_login_form(self, form: Form) -> bool:
        if form.method != "post":
            return False
        names = " ".join(form.input_names()).lower()
        return any(pf in names for pf in _PW_FIELDS)

    def _field(self, form: Form, candidates) -> str | None:
        for name in form.input_names():
            if name.lower() in candidates:
                return name
        for name in form.input_names():
            if any(c in name.lower() for c in candidates):
                return name
        return None

    def _load_passwords(self, config: Config) -> list[str]:
        path = getattr(config, "wordlist", "") or ""
        if path:
            try:
                lines = [ln.strip() for ln in
                         Path(path).read_text(encoding="utf-8", errors="replace")
                         .splitlines() if ln.strip()]
                if lines:
                    return lines
            except Exception:
                pass
        return list(load_lines("wordlists/common-passwords.txt"))

    def _submit(self, http: HttpClient, form: Form, ufield, pfield, user, pw):
        data = dict(form.inputs)
        if ufield:
            data[ufield] = user
        data[pfield] = pw
        return http.post(form.action, data=data, allow_redirects=False)

    def _profile(self, resp) -> dict:
        if resp is None:
            return {}
        body = (resp.text or "").lower()
        return {
            "status": resp.status_code,
            "location": resp.headers.get("Location", ""),
            "len": len(resp.text or ""),
            "has_fail": any(m in body for m in _FAIL_MARKERS),
            "set_cookie": resp.headers.get("Set-Cookie", ""),
            "lockout": any(m in body for m in _LOCKOUT_MARKERS)
                       or resp.status_code == 429,
        }

    def _looks_success(self, base: dict, cur: dict) -> bool:
        if not cur:
            return False
        signals = 0
        if cur["status"] in (301, 302, 303, 307, 308) and \
                cur["location"] != base.get("location"):
            signals += 2
        if base.get("has_fail") and not cur["has_fail"]:
            signals += 2
        if cur["set_cookie"] and cur["set_cookie"] != base.get("set_cookie"):
            signals += 1
        if base.get("len") and abs(cur["len"] - base["len"]) / max(base["len"], 1) > 0.3:
            signals += 1
        return signals >= 3

    def _attack_form(self, target, http, form, users, passwords, max_attempts):
        pfield = self._field(form, _PW_FIELDS)
        ufield = self._field(form, _USER_FIELDS)
        if not pfield:
            return []

        # Failure baseline with an obviously-wrong credential.
        base = self._profile(self._submit(http, form, ufield, pfield,
                                          "wr_nouser_zzz", "wr_nopass_zzz"))
        findings: list[Finding] = []
        attempts = 0
        locked = False

        for user in users:
            for pw in passwords:
                if attempts >= max_attempts:
                    break
                attempts += 1
                cur = self._profile(self._submit(http, form, ufield, pfield, user, pw))
                if cur.get("lockout"):
                    locked = True
                    break
                if self._looks_success(base, cur):
                    findings.append(Finding(
                        id=f"BRUTE-{len(findings)+1:03d}",
                        title=f"Weak/guessable credentials accepted "
                              f"({user})",
                        severity=Severity.CRITICAL,
                        owasp="A07:2021 - Identification & Authentication Failures",
                        cwe="CWE-521", cvss=9.8, location=form.action,
                        confidence="PROBABLE",
                        description=f"The login at {form.action} accepted a common "
                                    f"password for user '{user}'.",
                        evidence=f"username={user!r}, password={pw!r} "
                                 f"(attempt {attempts})",
                        impact="Account takeover — an attacker can log in directly.",
                        remediation="Change this password immediately. Enforce a "
                                    "strong password policy, add rate limiting / "
                                    "account lockout, and enable MFA.",
                        poc=f"Login as {user} with password '{pw}' at {form.action}",
                        references=["https://cwe.mitre.org/data/definitions/521.html"]))
                    break  # one weak cred per user is enough
            if locked or attempts >= max_attempts:
                break

        if locked:
            findings.append(Finding(
                id="BRUTE-LOCK-001",
                title="Account lockout / rate limiting active (good)",
                severity=Severity.INFO,
                owasp="A07:2021 - Identification & Authentication Failures",
                cwe="", cvss=0.0, location=form.action, confidence="CONFIRMED",
                description="The login triggered lockout/rate-limiting during "
                            "guessing — a healthy brute-force defense.",
                evidence=f"lockout signalled after {attempts} attempt(s)",
                impact="Positive control; no action needed.",
                remediation="Keep it; consider MFA as well.",
                references=[]))
        elif attempts >= 20 and not any(f.id.startswith("BRUTE-0") for f in findings):
            findings.append(Finding(
                id="BRUTE-NOPROT-001",
                title="No brute-force protection (no lockout/rate-limit observed)",
                severity=Severity.MEDIUM,
                owasp="A07:2021 - Identification & Authentication Failures",
                cwe="CWE-307", cvss=5.3, location=form.action,
                confidence="PROBABLE",
                description=f"{attempts} login attempts ran with no lockout, rate "
                            "limiting, or CAPTCHA — the form is open to automated "
                            "guessing.",
                evidence=f"{attempts} attempts, no lockout/429/captcha observed",
                impact="Attackers can brute-force credentials at scale.",
                remediation="Add account lockout / exponential backoff, rate "
                            "limiting, CAPTCHA after failures, and MFA.",
                references=["https://cwe.mitre.org/data/definitions/307.html"]))
        return findings

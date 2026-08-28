"""Headless-browser DOM XSS detection + screenshot evidence (optional).

Uses Playwright when available. Injects a marker payload into URL fragments and
query parameters, loads the page in a real browser, and detects whether the
payload's JavaScript actually executed in the DOM (true DOM-based XSS that
text-based scanners cannot see). Also captures a screenshot per finding.

Gracefully degrades: if Playwright (or its browser) is not installed, or
--browser was not passed, the check returns nothing.
"""
from __future__ import annotations

from pathlib import Path

from webrecon.checks.base import Check
from webrecon.core.config import Config
from webrecon.core.crawler import CrawlData
from webrecon.core.http_client import HttpClient
from webrecon.core.target import Target
from webrecon.model.finding import Finding
from webrecon.model.severity import Severity


_TOKEN = "WRDOMXSS1337"
# Payloads placed in fragment/param; execute only if a DOM sink is vulnerable.
_PAYLOADS = [
    f'"><img src=x onerror=window.__wrxss("{_TOKEN}")>',
    f"'><img src=x onerror=window.__wrxss('{_TOKEN}')>",
    f'<img src=x onerror=window.__wrxss("{_TOKEN}")>',
]
_MAX_URLS = 25


def _playwright_available() -> bool:
    try:
        import playwright.sync_api  # noqa: F401
        return True
    except Exception:
        return False


class BrowserDomXssCheck(Check):
    name = "domxss"
    description = "DOM-based XSS via a real headless browser (needs Playwright)."

    def run(self, target: Target, http: HttpClient, crawl: CrawlData,
            config: Config) -> list[Finding]:
        if not getattr(config, "browser", False):
            return []
        if not _playwright_available():
            return []
        try:
            from playwright.sync_api import sync_playwright
        except Exception:
            return []

        shots = Path(config.output_dir) / "screenshots"
        shots.mkdir(parents=True, exist_ok=True)
        findings: list[Finding] = []
        # Candidate URLs: crawled URLs + fragment tests on the homepage.
        urls = list(dict.fromkeys([target.url("/")] + crawl.urls))[:_MAX_URLS]

        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                for idx, base in enumerate(urls):
                    hit = self._test_url(browser, base, shots, idx)
                    if hit:
                        findings.append(hit)
                browser.close()
        except Exception:
            return findings
        return findings

    def _test_url(self, browser, base: str, shots: Path, idx: int):
        for payload in _PAYLOADS:
            for target_url in (f"{base}#{payload}",
                               (base + ("&" if "?" in base else "?")
                                + f"q={payload}")):
                context = browser.new_context()
                page = context.new_page()
                fired = {"hit": False}
                try:
                    page.expose_function(
                        "__wrxss", lambda t: fired.__setitem__("hit", True))
                    page.goto(target_url, wait_until="load", timeout=8000)
                    page.wait_for_timeout(500)
                except Exception:
                    context.close()
                    continue
                if fired["hit"]:
                    shot = shots / f"domxss_{idx}.png"
                    try:
                        page.screenshot(path=str(shot))
                    except Exception:
                        shot = None
                    context.close()
                    return Finding(
                        id=f"DOMXSS-{idx:03d}",
                        title="DOM-based XSS (executed in browser)",
                        severity=Severity.HIGH, owasp="A03:2021 - Injection",
                        cwe="CWE-79", cvss=6.1, location=target_url,
                        confidence="CONFIRMED",
                        description="A payload placed in the URL executed "
                                    "JavaScript in the page's DOM (client-side "
                                    "sink), confirmed in a real browser.",
                        evidence=f"payload executed: {payload}"
                                 + (f"; screenshot: {shot}" if shot else ""),
                        impact="Arbitrary JavaScript in the victim's browser "
                               "(session theft, account takeover).",
                        remediation="Avoid dangerous DOM sinks (innerHTML, "
                                    "document.write, eval) with URL data; encode "
                                    "output; use a strict CSP.",
                        poc=f"Open in a browser: {target_url}",
                        references=["https://owasp.org/www-community/attacks/"
                                    "DOM_Based_XSS"])
                context.close()
        return None

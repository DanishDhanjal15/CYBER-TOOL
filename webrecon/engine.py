"""The scan orchestrator: recon -> crawl -> run checks -> collect results."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from rich.console import Console

from webrecon.checks import all_checks, checks_by_names
from webrecon.core.config import Config
from webrecon.core.crawler import crawl as crawl_site
from webrecon.core.http_client import HttpClient
from webrecon.core.target import Target
from webrecon.model.finding import Finding, ScanResult
from webrecon.recon import dns_info, ports, tls, fingerprint, files


class Engine:
    def __init__(self, target: Target, config: Config,
                 console: Console | None = None):
        self.target = target
        self.config = config
        self.console = console or Console()
        self.http = HttpClient(config)

    def _log(self, message: str) -> None:
        self.console.print(message)

    def run(self) -> ScanResult:
        started = datetime.now(timezone.utc)
        result = ScanResult(target=self.target.base_url,
                            started_at=started.isoformat())
        t0 = time.monotonic()

        # ---- Recon -------------------------------------------------------
        self._log("[bold cyan]>>[/] Recon: DNS")
        dns_data, dns_findings = dns_info.gather(self.target)
        result.recon["dns"] = dns_data
        result.extend(dns_findings)

        self._log("[bold cyan]>>[/] Recon: port scan")
        result.recon["ports"] = ports.scan(self.target, timeout=1.2,
                                            threads=max(20, self.config.threads))

        self._log("[bold cyan]>>[/] Recon: TLS / certificate")
        tls_info, tls_findings = tls.gather(self.target)
        result.recon["tls"] = tls_info
        result.extend(tls_findings)

        self._log("[bold cyan]>>[/] Recon: technology fingerprint")
        result.recon["fingerprint"] = fingerprint.gather(self.target, self.http)

        self._log("[bold cyan]>>[/] Recon: sensitive files")
        files_info, files_findings = files.gather(
            self.target, self.http, threads=self.config.threads)
        result.recon["files"] = files_info
        result.extend(files_findings)

        if not self.target.is_ip:
            self._log("[bold cyan]>>[/] Recon: subdomains / takeover")
            from webrecon.recon import subdomains, email_security
            sub_info, sub_findings = subdomains.scan(
                self.target, self.http, threads=max(20, self.config.threads))
            result.recon["subdomains"] = sub_info
            result.extend(sub_findings)

            self._log("[bold cyan]>>[/] Recon: email security (SPF/DMARC)")
            email_info, email_findings = email_security.gather(self.target)
            result.recon["email"] = email_info
            result.extend(email_findings)

            self._log("[bold cyan]>>[/] Recon: WHOIS / RDAP / ASN")
            from webrecon.recon import whois_asn
            result.recon["whois"] = whois_asn.gather(self.target)

        # ---- Crawl -------------------------------------------------------
        self._log(f"[bold cyan]>>[/] Crawling (depth={self.config.depth}, "
                  f"max={self.config.max_urls}) ...")

        def _progress(url, count):
            if self.config.verbose:
                self._log(f"   crawled [{count}] {url}")

        crawl_data = crawl_site(self.target, self.http,
                                depth=self.config.depth,
                                max_urls=self.config.max_urls,
                                progress=_progress)
        self._log(f"   found {crawl_data.url_count} URL(s), "
                  f"{crawl_data.form_count} form(s), "
                  f"{len(crawl_data.param_targets())} param(s)")

        # ---- Wayback historical-URL discovery (domain targets) -----------
        if not self.target.is_ip and self.config.wayback:
            try:
                from webrecon.recon.wayback import discover_urls
                from urllib.parse import urlparse, parse_qs
                hist = discover_urls(self.target.host, self.target.scheme,
                                     limit=self.config.max_urls)
                added = 0
                for u in hist:
                    if u not in crawl_data.urls and self.target.in_scope(u):
                        crawl_data.urls.append(u)
                        qs = parse_qs(urlparse(u).query)
                        if qs:
                            crawl_data.params.setdefault(u, list(qs.keys()))
                        added += 1
                if added:
                    self._log(f"[bold cyan]>>[/] Wayback: added {added} "
                              "historical URL(s)")
            except Exception as exc:
                self._log(f"   [red]Wayback lookup failed: {exc}[/]")

        # ---- OpenAPI / Swagger seeding (optional) ------------------------
        if self.config.openapi:
            try:
                from webrecon.core import openapi as _oa
                spec = _oa.load_spec(self.config.openapi, self.http)
                extra = _oa.to_crawl(self.target, spec)
                _oa.merge(crawl_data, extra)
                self._log(f"[bold cyan]>>[/] OpenAPI: added "
                          f"{extra.url_count} endpoint(s), "
                          f"{extra.form_count} operation(s)")
            except Exception as exc:
                self._log(f"   [red]OpenAPI load failed: {exc}[/]")

        # ---- OAST listener (optional, for blind-vuln confirmation) -------
        oast_server = None
        if getattr(self.config, "oast", False):
            try:
                from webrecon.oast import OASTServer
                public = self.config.oast_host or None
                oast_server = OASTServer(public_host=public)
                oast_server.start()
                self.config.oast_server = oast_server  # type: ignore[attr-defined]
                self._log(f"[bold cyan]>>[/] OAST listener at "
                          f"http://{oast_server.public}")
            except Exception as exc:
                self._log(f"   [red]OAST failed to start: {exc}[/]")

        # ---- Checks ------------------------------------------------------
        checks = (checks_by_names(self.config.checks)
                  if self.config.checks else all_checks())
        # Opt-in brute-force: add it when explicitly enabled via --bruteforce.
        if getattr(self.config, "bruteforce", False) and \
                not any(c.name == "bruteforce" for c in checks):
            checks = checks + checks_by_names(["bruteforce"])
            self._log("[yellow]>>[/] Brute-force audit enabled (opt-in, "
                      f"max {getattr(self.config, 'max_attempts', 200)} attempts)")
        self._log(f"[bold cyan]>>[/] Running {len(checks)} vulnerability check(s)")
        for check in checks:
            try:
                new = check.run(self.target, self.http, crawl_data, self.config)
            except Exception as exc:  # a broken check must not kill the scan
                if self.config.verbose:
                    self._log(f"   [red]check '{check.name}' errored: {exc}[/]")
                new = []
            if new:
                self._log(f"   [yellow]{check.name}[/]: {len(new)} finding(s)")
            result.extend(new)

        # ---- Analysis: dedupe + correlate into attack chains -------------
        from webrecon.analysis.dedup import dedup
        from webrecon.analysis.correlate import correlate
        raw_count = len(result.findings)
        result.findings = dedup(result.findings)
        chains = correlate(result.findings)
        if raw_count != len(result.findings) or chains:
            self._log(f"[bold cyan]>>[/] Analysis: {raw_count} -> "
                      f"{len(result.findings)} after dedup, "
                      f"{len(chains)} attack chain(s)")
        result.extend(chains)

        # ---- Finalise ----------------------------------------------------
        finished = datetime.now(timezone.utc)
        result.finished_at = finished.isoformat()
        result.duration_seconds = time.monotonic() - t0
        result.stats = {
            "urls_crawled": crawl_data.url_count,
            "forms_found": crawl_data.form_count,
            "params_found": len(crawl_data.param_targets()),
            "requests_sent": self.http.request_count,
            "checks_run": len(checks),
        }
        if oast_server is not None:
            result.stats["oast_interactions"] = oast_server.total()
            oast_server.stop()

        self.http.close()
        return result

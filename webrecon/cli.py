"""WebRecon command-line interface.

Usage:
    webrecon scan <url-or-ip> [options]
    webrecon list-checks
"""
from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console

from webrecon import __version__
from webrecon.checks import available_names
from webrecon.core.config import Config
from webrecon.core.target import parse_target, TargetError
from webrecon.engine import Engine
from webrecon.model.severity import Severity
from webrecon.report import console_report, json_report, html_report


BANNER = r"""
 _    _      _     ____
| |  | | ___| |__ |  _ \ ___  ___ ___  _ __
| |  | |/ _ \ '_ \| |_) / _ \/ __/ _ \| '_ \
| |/\| |  __/ |_) |  _ <  __/ (_| (_) | | | |
|__/\__|\___|_.__/|_| \_\___|\___\___/|_| |_|
       authorized web security scanner
"""

DISCLAIMER = (
    "WebRecon is for AUTHORIZED security testing only. Scan systems you own or "
    "have explicit written permission to test. Unauthorized scanning may be "
    "illegal in your jurisdiction."
)


def _confirm_authorization(console: Console, target: str, assume: bool) -> bool:
    if assume:
        return True
    console.print(f"[yellow]{DISCLAIMER}[/]")
    try:
        answer = input(f"Do you have permission to scan {target}? [y/N] ").strip()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer.lower() in ("y", "yes")


def _parse_headers(header_args, bearer) -> dict:
    headers: dict[str, str] = {}
    for h in header_args or []:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    return headers


def _build_config(args) -> Config:
    if args.config:
        cfg = Config.from_yaml(args.config)
    else:
        cfg = Config()
    # A profile expands first; explicit flags below still override it.
    if args.profile:
        cfg.profile = args.profile
        cfg.apply_profile()
    formats = ([f.strip() for f in args.format.split(",")] if args.format else None)
    checks = ([c.strip() for c in args.checks.split(",")] if args.checks else None)
    cfg.apply_overrides(
        target=args.target,
        output_dir=args.output,
        formats=formats,
        checks=checks,
        aggressive=args.aggressive or None,
        threads=args.threads,
        timeout=args.timeout,
        rate_limit=args.rate_limit,
        depth=args.depth if not args.profile else (args.depth if args.depth != 2 else None),
        max_urls=args.max_urls if not args.profile else (args.max_urls if args.max_urls != 200 else None),
        respect_robots=args.respect_robots or None,
        verbose=args.verbose or None,
        authorized=args.authorize or None,
        cookie=args.cookie or None,
        openapi=args.openapi or None,
        templates_dir=args.templates_dir or None,
        oast=args.oast or None,
        oast_host=args.oast_host or None,
        browser=args.browser or None,
        cve_db=args.cve_db or None,
        db=args.db or None,
        no_store=args.no_store or None,
        diff=args.diff or None,
        baseline=args.baseline or None,
        bruteforce=args.bruteforce or None,
        wordlist=args.wordlist or None,
        username=args.username or None,
        max_attempts=args.max_attempts,
        rl_burst=args.rl_burst,
        wayback=args.wayback or None,
    )
    extra = _parse_headers(args.header, args.auth_bearer)
    if extra:
        cfg.extra_headers = extra
    return cfg


def _run_scan(args) -> int:
    console = Console()
    console.print(f"[bold cyan]{BANNER}[/]")

    try:
        target = parse_target(args.target)
    except TargetError as exc:
        console.print(f"[bold red]Target error:[/] {exc}")
        return 2

    if not _confirm_authorization(console, target.base_url, args.authorize):
        console.print("[red]Authorization not confirmed. Aborting.[/]")
        return 3

    cfg = _build_config(args)
    console.print(f"[green]Scanning[/] {target.base_url} "
                  f"({', '.join(target.ip_addresses) or 'no-ip'})\n")

    engine = Engine(target, cfg, console=console)
    result = engine.run()

    console.print()
    console_report.render(result, console=console)

    # Write file reports. Sanitise the host (dots/colons) so the extension is
    # appended cleanly and the timestamp is preserved (keeps runs unique).
    out_dir = Path(cfg.output_dir)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    safe = target.host.replace(":", "_").replace(".", "-")
    stem = f"webrecon_{safe}_{stamp}"
    if "json" in cfg.formats:
        p = json_report.write(result, out_dir / f"{stem}.json")
        console.print(f"[dim]JSON report:[/] {p}")
    if "html" in cfg.formats:
        p = html_report.write(result, out_dir / f"{stem}.html")
        console.print(f"[dim]HTML report:[/] {p}")
    if "sarif" in cfg.formats:
        from webrecon.report import sarif_report
        p = sarif_report.write(result, out_dir / f"{stem}.sarif")
        console.print(f"[dim]SARIF report:[/] {p}")
    if "har" in cfg.formats:
        from webrecon.report import har_report
        p = har_report.write(result, out_dir / f"{stem}.har")
        console.print(f"[dim]HAR traffic log:[/] {p} "
                      f"({len(result.transactions)} transactions)")

    # Persist to history + optional baseline/diff.
    if not cfg.no_store:
        try:
            from webrecon.storage.db import Store
            store = Store(cfg.db)
            prev_id = store.previous_scan_id(result.target)
            scan_id = store.save_scan(result)
            console.print(f"[dim]Saved to history:[/] {cfg.db} (scan #{scan_id})")
            if cfg.baseline:
                store.set_baseline(scan_id)
                console.print(f"[dim]Marked scan #{scan_id} as baseline.[/]")
            if cfg.diff:
                base_id = store.baseline_scan_id(result.target) or prev_id
                if base_id and base_id != scan_id:
                    _print_diff(store, scan_id, base_id, console)
                else:
                    console.print("[dim]No previous scan to diff against.[/]")
            store.close()
        except Exception as exc:
            console.print(f"[red]History store error:[/] {exc}")

    # CI-friendly exit code: non-zero if High/Critical present.
    counts = result.counts()
    if counts[Severity.CRITICAL.value] or counts[Severity.HIGH.value]:
        return 1
    return 0


def _print_diff(store, current_id, baseline_id, console) -> None:
    from webrecon.analysis.diff import diff_scans
    from rich.table import Table
    d = diff_scans(store, current_id, baseline_id)
    s = d["summary"]
    console.print(f"\n[bold]Diff vs scan #{baseline_id}:[/] "
                  f"[red]+{s['new']} new[/], [green]-{s['fixed']} fixed[/], "
                  f"{s['unchanged']} unchanged")
    if d["new"]:
        t = Table(title="NEW findings", show_header=True, header_style="bold red")
        t.add_column("Sev"); t.add_column("Title"); t.add_column("Location")
        for f in d["new"][:30]:
            t.add_row(f["severity"], f["title"], f["location"] or "-")
        console.print(t)
    if d["fixed"]:
        console.print(f"[green]Fixed since baseline:[/] "
                      + ", ".join(f["title"] for f in d["fixed"][:10]))


def _emit(result, out_dir: str, name: str, formats, console) -> int:
    """Shared: print a console summary, write reports, return an exit code."""
    console.print()
    console_report.render(result, console=console)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-") or "scan"
    stem = f"webrecon_{safe}_{stamp}"
    from webrecon.report import write_all
    for fmt, path in write_all(result, out_dir, stem, formats).items():
        console.print(f"[dim]{fmt.upper()} report:[/] {path}")
    counts = result.counts()
    if counts[Severity.CRITICAL.value] or counts[Severity.HIGH.value]:
        return 1
    return 0


def _run_cicd(args) -> int:
    console = Console()
    console.print("[bold cyan]WebRecon · CI/CD workflow scanner[/]\n")
    from webrecon.cicd import scanner
    root = Path(args.path)
    if not root.exists():
        console.print(f"[red]Path not found:[/] {root}")
        return 2
    console.print(f"Scanning CI/CD definitions under [bold]{root}[/] …")
    result = scanner.scan_path(str(root))
    console.print(f"Files scanned: {result.stats.get('files_scanned', 0)} "
                  f"({', '.join(result.stats.get('platforms', [])) or 'none'})")
    formats = [f.strip() for f in args.format.split(",")]
    return _emit(result, args.output, f"cicd-{root.name}", formats, console)


def _run_mlscan(args) -> int:
    console = Console()
    console.print("[bold cyan]WebRecon · ML backdoor / model supply-chain scanner[/]\n")
    from webrecon.mlscan import pipeline_scan
    root = Path(args.path)
    if not root.exists():
        console.print(f"[red]Path not found:[/] {root}")
        return 2
    console.print(f"Scanning model artifacts & ML code under [bold]{root}[/] …")
    result = pipeline_scan.scan_path(str(root))
    console.print(f"Code files scanned: {result.stats.get('code_files_scanned', 0)}")
    formats = [f.strip() for f in args.format.split(",")]
    return _emit(result, args.output, f"mlscan-{root.name}", formats, console)


def _run_predict(args) -> int:
    console = Console()
    console.print("[bold cyan]WebRecon · HPC / data-centre early-failure prediction[/]\n")
    from webrecon.reliability import predict
    path = Path(args.telemetry)
    if not path.exists():
        console.print(f"[red]Telemetry file not found:[/] {path}")
        return 2
    console.print(f"Analyzing telemetry [bold]{path.name}[/] …")
    result = predict.analyze(str(path))
    st = result.stats
    console.print(f"Records: {st.get('records', 0)} · components: "
                  f"{st.get('components', 0)} · signals: "
                  f"{', '.join(st.get('signals_detected', [])) or 'none'} · "
                  f"at-risk: {st.get('at_risk', 0)}")
    formats = [f.strip() for f in args.format.split(",")]
    return _emit(result, args.output, f"predict-{path.stem}", formats, console)


def _run_request(args) -> int:
    """Manual HTTP requester — send one request, show raw request + response."""
    console = Console()
    from webrecon.core.http_client import HttpClient
    from webrecon.core.http_trace import render_request, render_response
    cfg = Config()
    headers = _parse_headers(args.header, args.auth_bearer)
    if headers:
        cfg.extra_headers = headers
    if args.timeout:
        cfg.timeout = args.timeout
    http = HttpClient(cfg)
    kwargs = {"allow_redirects": args.follow}
    if args.data is not None:
        kwargs["data"] = args.data
    resp = http.request(args.method.upper(), args.url, **kwargs)
    txn = http.last_transaction()
    if txn is None:
        console.print("[red]Request failed (no response).[/]")
        return 1
    console.print("[bold cyan]── REQUEST ──[/]")
    console.print(f"[dim]{render_request(txn)}[/]")
    console.print("\n[bold cyan]── RESPONSE ──[/]")
    status = txn.get("status", 0)
    color = "green" if 200 <= status < 300 else ("yellow" if status < 400 else "red")
    console.print(f"[{color}]{render_response(txn)}[/]")
    http.close()
    return 0


def _run_proxy(args) -> int:
    console = Console()
    from webrecon.proxy import run_proxy
    return run_proxy(host=args.host, port=args.port, out=args.output,
                     mitm=args.mitm, console=console)


def _run_fix(args) -> int:
    console = Console()
    from webrecon import remediate
    from webrecon.core.target import parse_target, TargetError
    try:
        target = parse_target(args.url)
    except TargetError as exc:
        console.print(f"[red]Bad target:[/] {exc}")
        return 2
    loopback = target.host.lower() in ("localhost", "127.0.0.1", "::1")
    if not (args.authorize or loopback):
        console.print("[red]Pass --authorize (or target localhost).[/]")
        return 3
    console.print("[bold cyan]WebRecon · Auto-Remediation[/]")
    cfg = Config()
    cfg.local_scan = True
    cfg.authorized = True
    cfg.no_store = True
    cfg.checks = ["headers", "cookies", "cors", "csp", "dirlisting", "methods",
                  "webrecon", "infodisclosure"]
    result = Engine(target, cfg, console=console).run()
    config_text, n = remediate.generate(result, args.stack or "")
    console.print()
    if args.apply:
        from pathlib import Path
        out = Path(args.apply if isinstance(args.apply, str) else "webrecon-hardening.conf")
        out.write_text(config_text + "\n", encoding="utf-8")
        console.print(f"[green]Wrote {n} fix(es) → {out}[/]")
    else:
        console.print(config_text)
        console.print(f"\n[green]{n} auto-fix(es) generated[/] "
                      f"(stack: {args.stack or remediate.detect_stack(result)}). "
                      "Use [bold]--apply <file>[/] to save.")
    return 0


def _run_badge(args) -> int:
    console = Console()
    from webrecon import badge
    return badge.run_badge(args.url, args.output, console,
                           authorize=args.authorize, db=args.db)


def _run_watch(args) -> int:
    console = Console()
    from webrecon import watch
    return watch.run_watch(args.url, console, interval=args.interval,
                           watch_dir=args.watch_dir)


def _run_predeploy(args) -> int:
    console = Console()
    from webrecon import predeploy
    if args.install_hook:
        return predeploy.install_hook(console)
    console.print("[bold cyan]WebRecon · Pre-Deploy Security Gate[/]")
    return predeploy.run_predeploy(args.url, args.fail_on, console,
                                   profile=args.profile, no_store=args.no_store)


def _run_monitor(args) -> int:
    console = Console()
    console.print("[bold cyan]WebRecon · continuous monitoring[/]")
    if not args.authorize:
        console.print("[red]Pass --authorize to confirm you may scan these "
                      "targets continuously.[/]")
        return 3

    targets = list(args.targets)
    if args.targets_file:
        try:
            targets += [ln.strip() for ln in
                        Path(args.targets_file).read_text(encoding="utf-8").splitlines()
                        if ln.strip() and not ln.strip().startswith("#")]
        except Exception as exc:
            console.print(f"[red]Cannot read targets file:[/] {exc}")
            return 2
    if not targets:
        console.print("[red]No targets given.[/]")
        return 2

    from webrecon.monitor.notify import Notifier
    from webrecon.monitor.runner import run_monitor, parse_interval
    try:
        interval_s = parse_interval(args.interval)
    except ValueError as exc:
        console.print(f"[red]{exc}[/]")
        return 2

    cfg = Config()
    if args.profile:
        cfg.profile = args.profile
        cfg.apply_profile()
    cfg.apply_overrides(
        authorized=True, db=args.db,
        checks=([c.strip() for c in args.checks.split(",")] if args.checks else None),
        verbose=args.verbose or None)

    notifier = Notifier(webhook=args.webhook or "", log_file=args.log_file or "",
                        email_to=args.email_to or "", smtp_host=args.smtp_host or "",
                        smtp_port=args.smtp_port, smtp_user=args.smtp_user or "",
                        smtp_pass=args.smtp_pass or "", console=console,
                        min_severity=args.min_severity)

    console.print(f"Targets: {len(targets)} · interval: {interval_s}s · "
                  f"alert>= {args.min_severity} · "
                  f"channels: {'webhook ' if args.webhook else ''}"
                  f"{'email ' if args.email_to else ''}"
                  f"{'log ' if args.log_file else ''}console")
    if args.once:
        console.print("[dim](single cycle: --once)[/]")
    return run_monitor(targets, cfg, notifier, interval_s, args.once, console)


def _run_history(args) -> int:
    console = Console()
    from webrecon.storage.db import Store
    from rich.table import Table
    from pathlib import Path as _P
    if not _P(args.db).exists():
        console.print(f"[yellow]No history database at[/] {args.db}")
        return 0
    store = Store(args.db)
    scans = store.list_scans(target=args.target, limit=args.limit)
    if not scans:
        console.print("[yellow]No scans recorded yet.[/]")
        store.close()
        return 0
    t = Table(title="Scan history", show_header=True, header_style="bold")
    for col in ("#", "Target", "When", "Risk", "Findings", "C/H/M/L/I", "Base"):
        t.add_column(col)
    for s in scans:
        import json as _j
        c = _j.loads(s["counts_json"] or "{}")
        chmli = "/".join(str(c.get(k, 0)) for k in
                         ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))
        t.add_row(str(s["id"]), s["target"], (s["started_at"] or "")[:19],
                  f"{s['risk_score']}", str(s["total_findings"]), chmli,
                  "★" if s["is_baseline"] else "")
    console.print(t)
    store.close()
    return 0


def _list_checks(_args) -> int:
    console = Console()
    console.print("[bold]Available checks:[/]")
    for name in available_names():
        console.print(f"  • {name}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webrecon",
        description="WebRecon — authorized web vulnerability scanner.")
    parser.add_argument("--version", action="version",
                        version=f"webrecon {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a target URL or IP.")
    scan.add_argument("target", help="URL or IP to scan (e.g. http://example.com)")
    scan.add_argument("-o", "--output", default="./reports",
                      help="Report output directory (default: ./reports)")
    scan.add_argument("-f", "--format", default="html,json",
                      help="Comma list of report formats: html,json,sarif,har")
    scan.add_argument("--profile", choices=["quick", "standard", "deep"],
                      default=None,
                      help="Preset depth/scope: quick, standard, or deep")
    scan.add_argument("--checks", default=None,
                      help="Comma list of check names to run (default: all)")
    scan.add_argument("--openapi", default=None,
                      help="Path or URL to an OpenAPI/Swagger spec to seed API "
                           "endpoints")
    scan.add_argument("--templates", default=None, dest="templates_dir",
                      help="Extra directory of YAML detection templates")
    scan.add_argument("--cve-db", default=None, dest="cve_db",
                      help="Path to a custom CVE JSON database")
    scan.add_argument("--db", default=None,
                      help="SQLite history DB path (default: webrecon.db)")
    scan.add_argument("--no-store", action="store_true",
                      help="Do not save this scan to the history database")
    scan.add_argument("--diff", action="store_true",
                      help="Show New/Fixed findings vs the previous scan of this "
                           "target")
    scan.add_argument("--baseline", action="store_true",
                      help="Mark this scan as the baseline for the target")
    scan.add_argument("--header", action="append", default=None, metavar="K: V",
                      help="Extra request header (repeatable), e.g. "
                           "--header 'X-Api-Key: abc'")
    scan.add_argument("--cookie", default=None,
                      help="Raw Cookie header for authenticated scans")
    scan.add_argument("--auth-bearer", default=None, metavar="TOKEN",
                      help="Shortcut for Authorization: Bearer <TOKEN>")
    scan.add_argument("--oast", action="store_true",
                      help="Start an OAST listener to confirm blind SSRF/RCE "
                           "(use --oast-host for a target-reachable address)")
    scan.add_argument("--oast-host", default=None, metavar="HOST:PORT",
                      help="Public host:port the target can reach for OAST callbacks")
    scan.add_argument("--browser", action="store_true",
                      help="Enable headless-browser DOM checks (needs Playwright)")
    scan.add_argument("--bruteforce", action="store_true",
                      help="Enable login weak-credential/brute-force audit (opt-in, "
                           "authorized only)")
    scan.add_argument("--wordlist", default=None,
                      help="Password list for brute-force (e.g. rockyou.txt); "
                           "default is a bundled top-100 list")
    scan.add_argument("--username", default=None,
                      help="Comma list of usernames to try (default: admin,root,...)")
    scan.add_argument("--max-attempts", type=int, default=None, dest="max_attempts",
                      help="Cap on total brute-force login attempts (default 200)")
    scan.add_argument("--rl-burst", type=int, default=None, dest="rl_burst",
                      help="Requests per rate-limiting probe burst (default 20)")
    scan.add_argument("--wayback", action="store_true",
                      help="Discover historical URLs via the Wayback Machine (recon)")
    scan.add_argument("--aggressive", action="store_true",
                      help="Enable intrusive tests (e.g. time-based SQLi)")
    scan.add_argument("--threads", type=int, default=10, help="Concurrency")
    scan.add_argument("--timeout", type=int, default=10,
                      help="Per-request timeout (seconds)")
    scan.add_argument("--rate-limit", type=float, default=0.0,
                      help="Max requests/second (0 = unlimited)")
    scan.add_argument("--depth", type=int, default=2, help="Crawl depth")
    scan.add_argument("--max-urls", type=int, default=200,
                      help="Max URLs to crawl")
    scan.add_argument("--respect-robots", action="store_true",
                      help="Obey robots.txt")
    scan.add_argument("--authorize", action="store_true",
                      help="Confirm you are authorized (skips the prompt)")
    scan.add_argument("--config", default=None, help="Path to a YAML config file")
    scan.add_argument("-v", "--verbose", action="store_true")
    scan.set_defaults(func=_run_scan)

    # CI/CD workflow scanner
    cicd = sub.add_parser("cicd", help="Scan CI/CD pipeline files for vulns + patches.")
    cicd.add_argument("path", help="Repo/directory containing CI/CD definitions")
    cicd.add_argument("-o", "--output", default="./reports")
    cicd.add_argument("-f", "--format", default="html,json",
                      help="html,json,sarif")
    cicd.set_defaults(func=_run_cicd)

    # ML backdoor / model supply-chain scanner
    ml = sub.add_parser("mlscan", help="Scan ML models/code for backdoors + fixes.")
    ml.add_argument("path", help="Model file or directory of models/ML code")
    ml.add_argument("-o", "--output", default="./reports")
    ml.add_argument("-f", "--format", default="html,json", help="html,json,sarif")
    ml.set_defaults(func=_run_mlscan)

    # HPC / data-centre early-failure prediction
    pred = sub.add_parser("predict", help="Predict early hardware failures from telemetry.")
    pred.add_argument("telemetry", help="Telemetry file (.csv or .json)")
    pred.add_argument("-o", "--output", default="./reports")
    pred.add_argument("-f", "--format", default="html,json", help="html,json")
    pred.set_defaults(func=_run_predict)

    mon = sub.add_parser("monitor",
                         help="Continuously scan target(s) and alert on new findings.")
    mon.add_argument("targets", nargs="*", help="One or more URLs/IPs to monitor")
    mon.add_argument("--targets-file", default=None,
                     help="File with one target per line")
    mon.add_argument("--interval", default="1h",
                     help="Scan interval: 30s/5m/1h/1d (default 1h)")
    mon.add_argument("--once", action="store_true",
                     help="Run a single cycle and exit (for cron / testing)")
    mon.add_argument("--min-severity", default="high",
                     choices=["critical", "high", "medium", "low", "info"],
                     help="Only alert on new findings at/above this severity")
    mon.add_argument("--webhook", default=None,
                     help="Webhook URL for alerts (Slack/Discord/Teams/generic)")
    mon.add_argument("--log-file", default=None, help="Append alerts to a JSONL file")
    mon.add_argument("--email-to", default=None)
    mon.add_argument("--smtp-host", default=None)
    mon.add_argument("--smtp-port", type=int, default=587)
    mon.add_argument("--smtp-user", default=None)
    mon.add_argument("--smtp-pass", default=None)
    mon.add_argument("--profile", choices=["quick", "standard", "deep"],
                     default="quick", help="Scan profile per cycle (default quick)")
    mon.add_argument("--checks", default=None, help="Comma list of checks to run")
    mon.add_argument("--db", default="webrecon.db", help="History DB path")
    mon.add_argument("--authorize", action="store_true",
                     help="Confirm you are authorized to scan these targets")
    mon.add_argument("-v", "--verbose", action="store_true")
    mon.set_defaults(func=_run_monitor)

    pd = sub.add_parser("predeploy",
                        help="Pre-deploy gate: auto-scan your LOCAL app, "
                             "pass/fail on findings.")
    pd.add_argument("url", nargs="?", default=None,
                    help="Local app URL (auto-detected if omitted)")
    pd.add_argument("--fail-on", default="high", dest="fail_on",
                    choices=["critical", "high", "medium", "low"],
                    help="Block deploy if a finding at/above this severity exists")
    pd.add_argument("--profile", choices=["quick", "standard", "deep"],
                    default="standard", help="Scan depth (default standard)")
    pd.add_argument("--no-store", action="store_true",
                    help="Do not save this scan to history")
    pd.add_argument("--install-hook", action="store_true",
                    help="Install a git pre-push hook that runs this gate")
    pd.set_defaults(func=_run_predeploy)

    fix = sub.add_parser("fix",
                         help="Scan and generate ready-to-apply fixes for your stack.")
    fix.add_argument("url", help="Target URL")
    fix.add_argument("--stack", choices=list(("nginx", "apache", "express",
                     "flask", "django", "generic")), default=None,
                     help="Web stack (auto-detected if omitted)")
    fix.add_argument("--apply", nargs="?", const="webrecon-hardening.conf",
                     default=None, help="Write the fixes to a file")
    fix.add_argument("--authorize", action="store_true")
    fix.set_defaults(func=_run_fix)

    bdg = sub.add_parser("badge",
                         help="Generate an SVG security-grade badge for your README.")
    bdg.add_argument("url", nargs="?", default=None,
                     help="Target URL (uses last scan from history if omitted)")
    bdg.add_argument("-o", "--output", default="security-badge.svg",
                     help="SVG output path")
    bdg.add_argument("--db", default="webrecon.db", help="History DB path")
    bdg.add_argument("--authorize", action="store_true")
    bdg.set_defaults(func=_run_badge)

    wat = sub.add_parser("watch",
                         help="Live security linter — re-scan on change / interval.")
    wat.add_argument("url", nargs="?", default=None,
                     help="Local app URL (auto-detected if omitted)")
    wat.add_argument("--interval", type=int, default=20,
                     help="Seconds between scans (default 20)")
    wat.add_argument("--watch-dir", default=None,
                     help="Re-scan when files in this dir change")
    wat.set_defaults(func=_run_watch)

    req = sub.add_parser("request", help="Send one HTTP request; show raw req+resp.")
    req.add_argument("url", help="Target URL")
    req.add_argument("-X", "--method", default="GET", help="HTTP method")
    req.add_argument("-H", "--header", action="append", default=None,
                     metavar="K: V", help="Request header (repeatable)")
    req.add_argument("-d", "--data", default=None, help="Request body")
    req.add_argument("--auth-bearer", default=None, metavar="TOKEN")
    req.add_argument("--follow", action="store_true", help="Follow redirects")
    req.add_argument("--timeout", type=int, default=10)
    req.set_defaults(func=_run_request)

    prx = sub.add_parser("proxy",
                         help="Run an intercepting proxy that logs all traffic.")
    prx.add_argument("-p", "--port", type=int, default=8081, help="Listen port")
    prx.add_argument("--host", default="127.0.0.1", help="Listen host")
    prx.add_argument("-o", "--output", default="proxy-traffic.har",
                     help="HAR file to write captured traffic to")
    prx.add_argument("--mitm", action="store_true",
                     help="Decrypt HTTPS (generates a CA to trust; needs "
                          "'cryptography'). Without it, HTTPS is tunnelled/"
                          "metadata-only.")
    prx.set_defaults(func=_run_proxy)

    hist = sub.add_parser("history", help="List past scans from the history DB.")
    hist.add_argument("--db", default="webrecon.db", help="History DB path")
    hist.add_argument("--target", default=None, help="Filter by target")
    hist.add_argument("--limit", type=int, default=25, help="Max rows")
    hist.set_defaults(func=_run_history)

    lst = sub.add_parser("list-checks", help="List available vulnerability checks.")
    lst.set_defaults(func=_list_checks)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130


if __name__ == "__main__":
    sys.exit(main())

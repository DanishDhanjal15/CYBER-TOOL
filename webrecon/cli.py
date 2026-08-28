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

    # CI-friendly exit code: non-zero if High/Critical present.
    counts = result.counts()
    if counts[Severity.CRITICAL.value] or counts[Severity.HIGH.value]:
        return 1
    return 0


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
                      help="Comma list of report formats: html,json,sarif")
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

"""Pre-deployment security gate — scan your LOCAL app before you ship it.

Auto-detects a running local dev server (common ports), runs a fast, local-
optimized scan, and gives a clear go/no-go verdict with a CI-friendly exit
code. The idea: catch vulnerabilities on localhost so a deploy only goes out
once it's clean. This is WebRecon's shift-left / pre-deploy feature.
"""
from __future__ import annotations

import socket

from rich.panel import Panel
from rich.table import Table

from webrecon.core.config import Config
from webrecon.core.target import parse_target, TargetError
from webrecon.engine import Engine
from webrecon.model.severity import Severity, risk_score, risk_band

# Common local dev-server ports, roughly ordered by popularity.
_DEV_PORTS = [3000, 5173, 8080, 8000, 5000, 4200, 3001, 8888, 9000, 8081,
              4000, 5001, 3333, 8443, 1313, 80, 8001, 7000, 4321, 5174]
_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
# External/edge checks that make no sense against localhost.
_SKIP = {"buckets", "waf", "domxss"}


def _http_alive(host: str, port: int, timeout: float = 0.6) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            data = s.recv(64)
            return data.startswith(b"HTTP/")
    except Exception:
        return False


def detect_local_app(host: str = "127.0.0.1", ports=None) -> list[str]:
    """Return URLs of local dev servers that answer HTTP."""
    found: list[str] = []
    for port in (ports or _DEV_PORTS):
        if _http_alive(host, port):
            scheme = "https" if port in (443, 8443) else "http"
            found.append(f"{scheme}://{host}:{port}")
    return found


def run_predeploy(url, fail_on, console, *, profile="standard",
                  no_store=False) -> int:
    # 1) Resolve the target — auto-detect if none was given.
    if not url:
        console.print("[dim]No URL given — probing local dev ports…[/]")
        candidates = detect_local_app()
        if not candidates:
            console.print("[red]No local dev server found on common ports.[/] "
                          "Start your app (e.g. npm run dev) or pass a URL: "
                          "[bold]webrecon predeploy http://localhost:3000[/]")
            return 2
        url = candidates[0]
        extra = (f"  (also saw {', '.join(candidates[1:])})"
                 if len(candidates) > 1 else "")
        console.print(f"[green]Detected local app:[/] [bold]{url}[/]{extra}\n")

    try:
        target = parse_target(url)
    except TargetError as exc:
        console.print(f"[red]Bad target:[/] {exc}")
        return 2

    # 2) Local-optimized config (auto-authorized — it's your own machine).
    cfg = Config()
    cfg.profile = profile
    cfg.apply_profile()
    cfg.local_scan = True
    cfg.authorized = True
    cfg.no_store = no_store
    from webrecon.checks import available_names
    names = [n.split(" ")[0] for n in available_names()]
    cfg.checks = [n for n in names if n not in _SKIP]

    console.print(f"[bold cyan]Pre-deploy scan[/] of {target.base_url} "
                  f"(profile: {profile})\n")
    result = Engine(target, cfg, console=console).run()

    # 3) Gate: count findings at/above the fail-on threshold.
    threshold = _RANK.get(fail_on.upper(), 4)
    blocking = [f for f in result.findings if f.severity.rank >= threshold]
    counts = result.counts()
    score = risk_score(result.findings)

    # 4) Verdict.
    console.print()
    _print_findings(result, console)
    passed = not blocking
    verdict = ("[bold green]✅  READY TO DEPLOY[/]" if passed else
               f"[bold red]❌  DEPLOY BLOCKED[/] — "
               f"{len(blocking)} issue(s) at/above {fail_on.upper()}")
    body = Table.grid(padding=(0, 2))
    body.add_column(justify="right", style="bold")
    body.add_column()
    body.add_row("Verdict", verdict)
    body.add_row("Risk score", f"{score}/100 ({risk_band(score)})")
    body.add_row("Findings",
                 " · ".join(f"{k}:{counts[k]}" for k in
                            ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")))
    body.add_row("Gate", f"fail-on = {fail_on.upper()}")
    console.print(Panel(body, title="[bold]WebRecon · Pre-Deploy Gate[/]",
                        border_style="green" if passed else "red"))
    if not passed:
        console.print("[dim]Fix the blocking issues above, then re-run before "
                      "deploying.[/]")
    return 0 if passed else 1


def _print_findings(result, console) -> None:
    findings = result.sorted_findings()
    if not findings:
        console.print("[green]No findings.[/]")
        return
    t = Table(show_header=True, header_style="bold", show_lines=False)
    t.add_column("Sev", no_wrap=True)
    t.add_column("Issue")
    t.add_column("Location", overflow="fold")
    for f in findings[:25]:
        t.add_row(f"[{f.severity.color}]{f.severity.value}[/]", f.title,
                  f.location or "-")
    console.print(t)
    if len(findings) > 25:
        console.print(f"[dim]… and {len(findings) - 25} more (see HTML report).[/]")


# ---- git pre-push hook installer ----------------------------------------
_HOOK = """#!/bin/sh
# WebRecon pre-deploy gate — blocks a push if the local app has HIGH/CRITICAL vulns.
# Start your dev server first. Skip once with:  git push --no-verify
echo "[WebRecon] pre-deploy security scan..."
python -m webrecon predeploy --fail-on high || {
  echo "[WebRecon] Deploy gate FAILED — fix the issues above or use --no-verify."
  exit 1
}
"""


def install_hook(console) -> int:
    from pathlib import Path
    hooks = Path(".git") / "hooks"
    if not hooks.exists():
        console.print("[red]No .git/hooks directory — run this inside a git "
                      "repository.[/]")
        return 2
    path = hooks / "pre-push"
    path.write_text(_HOOK, encoding="utf-8")
    try:
        path.chmod(0o755)
    except Exception:
        pass
    console.print(f"[green]Installed pre-push hook:[/] {path}")
    console.print("[dim]Now every 'git push' runs a local security scan first. "
                  "Bypass once with 'git push --no-verify'.[/]")
    return 0

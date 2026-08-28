"""Live security linter — keep scanning your local app as you code.

Re-scans on a fixed interval, or (with --watch-dir) whenever your source files
change, and prints only what's NEW or FIXED since the last scan. Like a test
watcher, but for vulnerabilities — security feedback while you're still coding.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path


def _dir_signature(path: str) -> float:
    latest = 0.0
    p = Path(path)
    if not p.exists():
        return 0.0
    for f in p.rglob("*"):
        if f.is_file() and "__pycache__" not in str(f) and ".git" not in str(f):
            try:
                latest = max(latest, f.stat().st_mtime)
            except Exception:
                continue
    return latest


def _scan(url, console):
    from webrecon.core.config import Config
    from webrecon.core.target import parse_target
    from webrecon.engine import Engine

    class _Silent:
        def print(self, *a, **k):
            pass
    cfg = Config()
    cfg.profile = "quick"; cfg.apply_profile()
    cfg.local_scan = True; cfg.authorized = True; cfg.no_store = True
    return Engine(parse_target(url), cfg, console=_Silent()).run()


def run_watch(url, console, *, interval=20, watch_dir=None) -> int:
    if not url:
        from webrecon.predeploy import detect_local_app
        console.print("[dim]Probing for a local dev server…[/]")
        found = detect_local_app()
        if not found:
            console.print("[red]No local app found. Start it or pass a URL.[/]")
            return 2
        url = found[0]
    console.print(f"[bold cyan]👀 Watching[/] {url}  "
                  + (f"(on changes in {watch_dir})" if watch_dir
                     else f"(every {interval}s)"))
    console.print("[dim]Ctrl+C to stop.[/]\n")

    prev: dict[str, object] = {}
    last_sig = None
    first = True
    try:
        while True:
            if watch_dir and not first:
                sig = _dir_signature(watch_dir)
                if sig == last_sig:
                    time.sleep(2)
                    continue
                last_sig = sig
                console.print("[dim]— change detected, re-scanning —[/]")
            first = False
            if watch_dir:
                last_sig = _dir_signature(watch_dir)

            try:
                result = _scan(url, console)
            except Exception as exc:
                console.print(f"[red]scan error:[/] {exc}")
                time.sleep(interval)
                continue

            cur = {f.fingerprint(): f for f in result.findings}
            new = [cur[k] for k in cur.keys() - prev.keys()]
            fixed = [prev[k] for k in prev.keys() - cur.keys()]
            stamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
            counts = result.counts()
            summary = "/".join(str(counts[s]) for s in
                               ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))

            if new:
                for f in sorted(new, key=lambda x: x.severity.rank, reverse=True):
                    console.print(f"[{f.severity.color}]  + {f.severity.value:8}[/]"
                                  f" {f.title}  [dim]{f.location}[/]")
            for f in fixed:
                console.print(f"[green]  - FIXED   [/] {f.title}")
            if not new and not fixed:
                console.print(f"[dim]{stamp}[/]  [green]no change[/]  "
                              f"(C/H/M/L/I {summary})")
            else:
                console.print(f"[dim]{stamp}[/]  {len(new)} new · {len(fixed)} "
                              f"fixed  (C/H/M/L/I {summary})\n")
            prev = cur
            if not watch_dir:
                time.sleep(interval)
    except KeyboardInterrupt:
        console.print("\n[yellow]watch stopped.[/]")
    return 0

"""Continuous-monitoring loop: periodically scan, diff, and alert on changes.

For each target, run a scan, persist it, diff against the previous scan, and
fire an alert when NEW findings appear. The first scan of a target becomes the
baseline (no alert). Reuses the Engine, the SQLite history store, and the diff
engine already built.
"""
from __future__ import annotations

import re
import time
from datetime import datetime, timezone

from webrecon.analysis.diff import diff_scans
from webrecon.core.target import parse_target, TargetError
from webrecon.engine import Engine
from webrecon.monitor.notify import Alert
from webrecon.storage.db import Store


def parse_interval(value: str) -> int:
    """'30s' / '5m' / '1h' / '2h' / '1d' / '3600' -> seconds."""
    value = str(value).strip().lower()
    m = re.fullmatch(r"(\d+)\s*([smhd]?)", value)
    if not m:
        raise ValueError(f"Bad interval: {value!r} (use e.g. 30m, 1h, 3600)")
    n = int(m.group(1))
    return n * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


class SilentConsole:
    def print(self, *a, **k):
        pass


def _one_cycle(target_str, cfg, store, notifier, console) -> None:
    try:
        target = parse_target(target_str)
    except TargetError as exc:
        console.print(f"[red]skip {target_str}: {exc}[/]")
        return

    stamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
    console.print(f"[dim]{stamp}[/] scanning [bold]{target.base_url}[/] …")
    result = Engine(target, cfg, console=SilentConsole()).run()

    prev_id = store.previous_scan_id(result.target)
    scan_id = store.save_scan(result)
    counts = result.counts()
    summary = "/".join(str(counts[k]) for k in
                       ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))
    console.print(f"   scan #{scan_id}: {len(result.findings)} findings "
                  f"(C/H/M/L/I = {summary})")

    if prev_id is None:
        console.print("   [dim]baseline established — no alert on first scan.[/]")
        return

    d = diff_scans(store, scan_id, prev_id)
    if d["new"]:
        alert = Alert(target=result.target, new=d["new"], fixed=d["fixed"],
                      scan_id=scan_id)
        fired = notifier.send(alert)
        if fired:
            console.print(f"   [bold]alerted[/] via: {', '.join(fired)}")
        else:
            console.print("   [dim]new findings below alert threshold.[/]")
    else:
        console.print("   [green]no new findings.[/]")
        if d["fixed"]:
            console.print(f"   [green]{len(d['fixed'])} fixed since last scan.[/]")


def run_monitor(targets, cfg, notifier, interval_s, once, console) -> int:
    store = Store(cfg.db)
    cycle = 0
    try:
        while True:
            cycle += 1
            console.print(f"[bold cyan]── monitor cycle {cycle} "
                          f"({datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} "
                          f"UTC) ──[/]")
            for t in targets:
                _one_cycle(t, cfg, store, notifier, console)
            if once:
                break
            console.print(f"[dim]sleeping {interval_s}s …[/]\n")
            time.sleep(interval_s)
    except KeyboardInterrupt:
        console.print("\n[yellow]monitor stopped.[/]")
    finally:
        store.close()
    return 0

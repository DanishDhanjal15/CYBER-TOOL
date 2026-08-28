"""Security-grade badge — a shareable SVG for your README.

Grades the target's latest scan (A–F) and writes a shields.io-style SVG plus
the Markdown to embed it. Put it next to your build badge — it updates every
time you re-run, and gently pressures the repo to stay secure.
"""
from __future__ import annotations

from pathlib import Path

from webrecon.model.severity import risk_score, risk_band

# grade -> (color, label-ish)
_COLORS = {"A": "#2ea043", "B": "#7bc043", "C": "#dfb317",
           "D": "#fe7d37", "F": "#e5534b", "?": "#9f9f9f"}


def grade(counts: dict) -> str:
    if counts.get("CRITICAL", 0):
        return "F"
    if counts.get("HIGH", 0):
        return "D"
    if counts.get("MEDIUM", 0):
        return "C"
    if counts.get("LOW", 0):
        return "B"
    return "A"


def _svg(grade_letter: str) -> str:
    color = _COLORS.get(grade_letter, _COLORS["?"])
    label, value = "security", grade_letter
    lw, vw = 62, 26            # label / value widths
    total = lw + vw
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20" role="img" aria-label="{label}: {value}">
  <title>{label}: {value}</title>
  <linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
  <clipPath id="r"><rect width="{total}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="{lw}" height="20" fill="#555"/>
    <rect x="{lw}" width="{vw}" height="20" fill="{color}"/>
    <rect width="{total}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <text x="{lw/2*10:.0f}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{(lw-12)*10:.0f}">{label}</text>
    <text x="{lw/2*10:.0f}" y="140" transform="scale(.1)" textLength="{(lw-12)*10:.0f}">{label}</text>
    <text x="{(lw+vw/2)*10:.0f}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)">{value}</text>
    <text x="{(lw+vw/2)*10:.0f}" y="140" transform="scale(.1)">{value}</text>
  </g>
</svg>'''


def run_badge(url, output, console, *, authorize=False, db="webrecon.db") -> int:
    counts = None
    score = 0
    if url:
        from webrecon.core.config import Config
        from webrecon.core.target import parse_target, TargetError
        from webrecon.engine import Engine
        try:
            target = parse_target(url)
        except TargetError as exc:
            console.print(f"[red]Bad target:[/] {exc}")
            return 2
        loopback = target.host.lower() in ("localhost", "127.0.0.1", "::1")
        if not (authorize or loopback):
            console.print("[red]Pass --authorize (or target localhost).[/]")
            return 3
        cfg = Config(); cfg.profile = "quick"; cfg.apply_profile()
        cfg.local_scan = True; cfg.authorized = True; cfg.no_store = True
        result = Engine(target, cfg, console=console).run()
        counts = result.counts()
        score = risk_score(result.findings)
    else:
        # Use the most recent scan from history.
        from webrecon.storage.db import Store
        import json as _j
        if not Path(db).exists():
            console.print(f"[yellow]No history DB at {db} — pass a URL to scan.[/]")
            return 2
        store = Store(db)
        scans = store.list_scans(limit=1)
        store.close()
        if not scans:
            console.print("[yellow]No scans recorded — pass a URL to scan.[/]")
            return 2
        counts = _j.loads(scans[0]["counts_json"] or "{}")
        score = scans[0]["risk_score"]

    g = grade(counts)
    out = Path(output)
    out.write_text(_svg(g), encoding="utf-8")
    console.print(f"[bold]Security grade:[/] [bold {'green' if g in 'AB' else 'red'}]"
                  f"{g}[/]  (risk {score}/100, {risk_band(score)})")
    console.print(f"[green]Badge written → {out}[/]")
    console.print("\n[dim]Embed in your README:[/]")
    console.print(f"![Security]({out.name})")
    return 0

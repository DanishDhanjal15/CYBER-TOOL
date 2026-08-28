"""Render a scan result to the terminal using rich."""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from webrecon.model.finding import ScanResult
from webrecon.model.severity import Severity, risk_score, risk_band


def render(result: ScanResult, console: Console | None = None) -> None:
    console = console or Console()
    counts = result.counts()
    score = risk_score(result.findings)
    band = risk_band(score)

    summary = Table.grid(padding=(0, 2))
    summary.add_column(justify="right", style="bold")
    summary.add_column()
    summary.add_row("Target", result.target)
    summary.add_row("Duration", f"{result.duration_seconds:.1f}s")
    summary.add_row("Requests", str(result.stats.get("requests_sent", 0)))
    summary.add_row("URLs crawled", str(result.stats.get("urls_crawled", 0)))
    summary.add_row("Risk score", f"[bold]{score}/100[/] ({band})")
    console.print(Panel(summary, title="[bold]WebRecon Scan Summary[/]",
                        border_style="cyan"))

    # Severity breakdown.
    bar = Table(show_header=True, header_style="bold")
    for sev in Severity:
        bar.add_column(sev.value, justify="center", style=sev.color)
    bar.add_row(*[str(counts[s.value]) for s in Severity])
    console.print(bar)

    findings = result.sorted_findings()
    if not findings:
        console.print("[bold green]No findings. (Still review manually.)[/]")
        return

    table = Table(show_header=True, header_style="bold", title="Findings",
                  show_lines=True)
    table.add_column("Sev", no_wrap=True)
    table.add_column("Title")
    table.add_column("Location", overflow="fold")
    table.add_column("OWASP", no_wrap=True)
    for f in findings:
        table.add_row(f"[{f.severity.color}]{f.severity.value}[/]", f.title,
                      f.location or "-", f.owasp.split(" - ")[0] if f.owasp else "-")
    console.print(table)
    console.print("[dim]Full details (evidence, impact, remediation) are in the "
                  "HTML/JSON report.[/]")

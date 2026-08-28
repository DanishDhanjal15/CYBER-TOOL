"""Render a scan result to a self-contained, styled HTML report."""
from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from webrecon.model.finding import ScanResult
from webrecon.model.severity import Severity, risk_score, risk_band

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


def _env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )


def write(result: ScanResult, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    template = _env().get_template("report.html.j2")
    score = risk_score(result.findings)
    html = template.render(
        result=result,
        findings=result.sorted_findings(),
        counts=result.counts(),
        severities=[s.value for s in Severity],
        score=score,
        band=risk_band(score),
        recon=result.recon,
        stats=result.stats,
    )
    path.write_text(html, encoding="utf-8")
    return path

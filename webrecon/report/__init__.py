"""Report renderers + a shared multi-format writer used by all subcommands."""
from __future__ import annotations

from pathlib import Path


def write_all(result, out_dir, stem: str, formats) -> dict:
    """Write the requested report formats and return {format: path}."""
    from . import json_report, html_report
    out: dict[str, Path] = {}
    p = Path(out_dir)
    if "json" in formats:
        out["json"] = json_report.write(result, p / f"{stem}.json")
    if "html" in formats:
        out["html"] = html_report.write(result, p / f"{stem}.html")
    if "sarif" in formats:
        from . import sarif_report
        out["sarif"] = sarif_report.write(result, p / f"{stem}.sarif")
    return out

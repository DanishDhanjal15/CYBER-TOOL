"""Write a scan result as machine-readable JSON."""
from __future__ import annotations

import json
from pathlib import Path

from webrecon.model.finding import ScanResult


def write(result: ScanResult, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result.to_dict(), indent=2, default=str),
                    encoding="utf-8")
    return path

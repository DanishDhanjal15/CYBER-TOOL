"""Bundled data files (payloads, wordlists, signatures) and a loader helper."""
from __future__ import annotations

from pathlib import Path
from functools import lru_cache

_DATA_DIR = Path(__file__).resolve().parent


@lru_cache(maxsize=None)
def load_lines(relpath: str) -> tuple[str, ...]:
    """Return non-empty, non-comment lines from a bundled data file."""
    path = _DATA_DIR / relpath
    lines: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            lines.append(line)
    return tuple(lines)

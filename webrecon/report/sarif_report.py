"""Export findings as SARIF 2.1.0 for CI / GitHub code-scanning integration."""
from __future__ import annotations

import json
from pathlib import Path

from webrecon.model.finding import ScanResult

# SARIF severity uses: error / warning / note.
_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
          "LOW": "note", "INFO": "note"}


def _rules(result: ScanResult) -> list[dict]:
    rules: dict[str, dict] = {}
    for f in result.findings:
        rid = f.id.rsplit("-", 1)[0] if "-" in f.id else f.id
        if rid in rules:
            continue
        rules[rid] = {
            "id": rid,
            "name": f.title,
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.description or f.title},
            "helpUri": (f.references[0] if f.references else ""),
            "properties": {"security-severity": str(f.cvss),
                           "owasp": f.owasp, "cwe": f.cwe},
        }
    return list(rules.values())


def write(result: ScanResult, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    results = []
    for f in result.sorted_findings():
        rid = f.id.rsplit("-", 1)[0] if "-" in f.id else f.id
        results.append({
            "ruleId": rid,
            "level": _LEVEL.get(f.severity.value, "warning"),
            "message": {"text": f"{f.title} — {f.impact} "
                                f"[confidence: {f.confidence}]"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.location or result.target}
                }
            }],
            "properties": {"severity": f.severity.value,
                           "confidence": f.confidence,
                           "evidence": f.evidence, "poc": f.poc,
                           "remediation": f.remediation},
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "WebRecon",
                "informationUri": "https://example.local/webrecon",
                "version": "0.1.0",
                "rules": _rules(result),
            }},
            "results": results,
        }],
    }
    path.write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
    return path

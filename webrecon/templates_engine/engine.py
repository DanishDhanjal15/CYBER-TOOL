"""A small Nuclei-style YAML template engine.

A template describes HTTP request(s) and matchers; when the matchers hit, a
Finding is produced. This makes the scanner extensible without writing Python:
drop a .yaml file in the templates directory (bundled or via --templates).

Template schema (subset of Nuclei):

    id: exposed-git-config
    info:
      name: Exposed .git/config
      severity: high            # critical/high/medium/low/info
      description: ...
      remediation: ...
      owasp: "A05:2021 - Security Misconfiguration"
      cwe: CWE-538
      reference: [https://...]
    requests:
      - method: GET
        path: ["/.git/config"]
        matchers-condition: and         # and | or (default or)
        matchers:
          - type: status
            status: [200]
          - type: word                  # word | regex | status
            part: body                  # body | header
            condition: or               # or | and (within this matcher)
            words: ["[core]", "[remote"]
          - type: regex
            part: body
            regex: ["repositoryformatversion"]
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

from webrecon.core.http_client import HttpClient
from webrecon.core.target import Target
from webrecon.model.finding import Finding
from webrecon.model.severity import Severity

_BUNDLED = Path(__file__).resolve().parent.parent / "data" / "templates"
_SEV = {s.value.lower(): s for s in Severity}


def load_templates(extra_dir: str | None = None) -> list[dict]:
    templates: list[dict] = []
    dirs = [_BUNDLED]
    if extra_dir:
        dirs.append(Path(extra_dir))
    for d in dirs:
        if not d.exists():
            continue
        for path in sorted(d.glob("*.yaml")) + sorted(d.glob("*.yml")):
            try:
                doc = yaml.safe_load(path.read_text(encoding="utf-8"))
                if isinstance(doc, dict) and doc.get("requests"):
                    doc["_source"] = str(path)
                    templates.append(doc)
            except Exception:
                continue
    return templates


def _part_text(resp, part: str) -> str:
    if part == "header":
        return "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    return resp.text or ""


def _match_one(resp, matcher: dict) -> bool:
    mtype = matcher.get("type")
    if mtype == "status":
        return resp.status_code in (matcher.get("status") or [])
    part = matcher.get("part", "body")
    text = _part_text(resp, part)
    cond = matcher.get("condition", "or")
    if mtype == "word":
        words = matcher.get("words") or []
        results = [w in text for w in words]
    elif mtype == "regex":
        pats = matcher.get("regex") or []
        results = [re.search(p, text, re.IGNORECASE | re.MULTILINE) is not None
                   for p in pats]
    else:
        return False
    if not results:
        return False
    return all(results) if cond == "and" else any(results)


def _eval_request(resp, req: dict) -> bool:
    matchers = req.get("matchers") or []
    if not matchers:
        return False
    cond = req.get("matchers-condition", "or")
    results = [_match_one(resp, m) for m in matchers]
    return all(results) if cond == "and" else any(results)


def run_templates(target: Target, http: HttpClient,
                  templates: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    for tpl in templates:
        info = tpl.get("info", {})
        sev = _SEV.get(str(info.get("severity", "info")).lower(), Severity.INFO)
        matched_location = None
        for req in tpl.get("requests", []):
            method = (req.get("method") or "GET").upper()
            for path in (req.get("path") or ["/"]):
                url = target.url(path) if path.startswith("/") else path
                resp = http.request(method, url)
                if resp is None:
                    continue
                if _eval_request(resp, req):
                    matched_location = url
                    break
            if matched_location:
                break
        if matched_location:
            findings.append(Finding(
                id=f"TPL-{tpl.get('id', 'unknown')}",
                title=info.get("name", tpl.get("id", "template match")),
                severity=sev, owasp=info.get("owasp", ""),
                cwe=info.get("cwe", ""),
                cvss=float(info.get("cvss", 0.0) or 0.0),
                location=matched_location, confidence="CONFIRMED",
                description=info.get("description", ""),
                evidence=f"template '{tpl.get('id')}' matched",
                impact=info.get("impact", "See template description."),
                remediation=info.get("remediation", ""),
                poc=f"curl -i '{matched_location}'",
                references=info.get("reference") or info.get("references") or []))
    return findings

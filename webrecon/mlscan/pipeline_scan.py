"""Heuristic scan of ML training / distributed-learning code and configs.

Complements the model-file scanner by looking at *how* models and data are
loaded and aggregated — the places a distributed / federated-learning
backdoor is introduced or left undefended:

  * unsafe deserialization (`torch.load` w/o weights_only, `pickle.load`,
    `trust_remote_code=True`, `yaml.load`)
  * federated aggregation with no robustness (plain FedAvg / mean, no Krum,
    trimmed-mean, Bulyan, update clipping, or differential privacy)
  * training data pulled from an unverified remote source

and pairs each with a concrete remediation.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from webrecon.model.finding import Finding, ScanResult
from webrecon.model.severity import Severity
from webrecon.mlscan.model_scan import scan_models


_CODE_EXT = {".py", ".ipynb", ".yaml", ".yml", ".json", ".cfg", ".toml", ".sh"}

_ROBUST_AGG = ("krum", "trimmed", "trimmed_mean", "median", "bulyan",
               "coordinate_median", "geometric_median", "clip", "clipping",
               "differential privacy", "differentialprivacy", "dp_sgd",
               "norm_bound", "robust")
_FED_MARKERS = ("federated", "fedavg", "federatedaveraging", "flower", "flwr",
                "client_update", "aggregate_fit", "secure_aggregation")


def _lineno(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def _scan_text(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    rel = str(path)
    low = text.lower()

    # 1) torch.load without weights_only=True
    for m in re.finditer(r"torch\.load\s*\(", text):
        window = text[m.start():m.start() + 200]
        if "weights_only" not in window:
            findings.append(Finding(
                id="ML-LOAD-001",
                title="torch.load without weights_only=True",
                severity=Severity.HIGH,
                owasp="A08:2021 - Software & Data Integrity Failures",
                cwe="CWE-502", cvss=8.1,
                location=f"{rel}:{_lineno(text, m.start())}", confidence="CONFIRMED",
                description="torch.load unpickles by default and will execute code "
                            "embedded in a malicious checkpoint.",
                evidence=window.split(chr(10))[0][:100],
                impact="A poisoned checkpoint runs arbitrary code on every node "
                       "that loads it.",
                remediation="Pass weights_only=True (PyTorch >=2.0) or load "
                            "safetensors; verify checksums of shared weights.",
                poc="torch.load(path, weights_only=True)",
                references=["https://pytorch.org/docs/stable/generated/"
                            "torch.load.html"]))

    # 2) pickle.load / joblib.load / yaml.load (unsafe)
    for pat, name, fix in (
        (r"pickle\.loads?\s*\(", "pickle.load",
         "Use a safe format (safetensors/JSON) or only unpickle trusted data."),
        (r"joblib\.load\s*\(", "joblib.load",
         "joblib.load unpickles; only load trusted files, prefer safetensors."),
        (r"yaml\.load\s*\((?![^)]*SafeLoader)", "yaml.load (unsafe)",
         "Use yaml.safe_load()."),
    ):
        for m in re.finditer(pat, text):
            findings.append(Finding(
                id="ML-LOAD-002", title=f"Unsafe deserialization: {name}",
                severity=Severity.MEDIUM,
                owasp="A08:2021 - Software & Data Integrity Failures",
                cwe="CWE-502", cvss=6.5,
                location=f"{rel}:{_lineno(text, m.start())}", confidence="CONFIRMED",
                description=f"{name} deserializes data that may execute code.",
                evidence=text[m.start():m.start()+80].split(chr(10))[0],
                impact="Code execution if the input is attacker-influenced.",
                remediation=fix, poc="", references=[
                    "https://cwe.mitre.org/data/definitions/502.html"]))

    # 3) trust_remote_code=True (HuggingFace)
    for m in re.finditer(r"trust_remote_code\s*=\s*True", text):
        findings.append(Finding(
            id="ML-HF-001", title="HuggingFace trust_remote_code=True",
            severity=Severity.HIGH,
            owasp="A08:2021 - Software & Data Integrity Failures", cwe="CWE-494",
            cvss=8.0, location=f"{rel}:{_lineno(text, m.start())}",
            confidence="CONFIRMED",
            description="Loading a model/dataset with trust_remote_code=True runs "
                        "arbitrary code shipped in the repo.",
            evidence="trust_remote_code=True",
            impact="A malicious model repo executes code on your training nodes.",
            remediation="Set trust_remote_code=False; if custom code is required, "
                        "vendor and review it, and pin the revision.",
            poc="from_pretrained(name, trust_remote_code=False, revision='<sha>')",
            references=["https://huggingface.co/docs/hub/security"]))

    # 4) Federated aggregation without robustness / backdoor defenses
    if any(k in low for k in _FED_MARKERS):
        if not any(r in low for r in _ROBUST_AGG):
            findings.append(Finding(
                id="ML-FED-001",
                title="Federated aggregation without robust/backdoor defenses",
                severity=Severity.MEDIUM,
                owasp="A08:2021 - Software & Data Integrity Failures",
                cwe="CWE-345", cvss=6.0, location=rel, confidence="POTENTIAL",
                description="Distributed/federated training averages client "
                            "updates with no robust aggregation, update clipping, "
                            "or differential privacy — the standard defenses "
                            "against model-poisoning / backdoor attacks.",
                evidence="federated markers present; no robust-aggregation keyword "
                         "found",
                impact="A few malicious clients can implant a backdoor (targeted "
                       "misclassification on a trigger) via poisoned updates.",
                remediation="Use robust aggregation (Krum / Multi-Krum, "
                            "trimmed-mean, median, Bulyan), clip client update "
                            "norms, add differential privacy, and monitor updates "
                            "for anomalies. Post-train, screen with Neural Cleanse "
                            "/ STRIP / activation clustering.",
                poc="# e.g. replace FedAvg with trimmed-mean + norm clipping\n"
                    "# agg = trimmed_mean(updates, beta=0.1)\n"
                    "# updates = [clip_norm(u, max_norm) for u in updates]",
                references=["https://arxiv.org/abs/1807.00459",
                            "https://arxiv.org/abs/1811.03761"]))

    # 5) Training data fetched from an unverified remote source
    for m in re.finditer(r"(urlretrieve|requests\.get|wget|hf_hub_download|"
                         r"load_dataset)\s*\(", text):
        window = text[max(0, m.start()-40):m.start()+160].lower()
        if ("data" in window or "train" in window or "dataset" in window) and \
                not any(h in window for h in ("sha256", "checksum", "hash",
                                              "verify", "revision")):
            findings.append(Finding(
                id="ML-DATA-001",
                title="Training data pulled from an unverified source",
                severity=Severity.LOW,
                owasp="A08:2021 - Software & Data Integrity Failures",
                cwe="CWE-345", cvss=4.0,
                location=f"{rel}:{_lineno(text, m.start())}", confidence="POTENTIAL",
                description="Data appears to be downloaded without integrity "
                            "verification — an avenue for data-poisoning backdoors.",
                evidence=text[m.start():m.start()+70].split(chr(10))[0],
                impact="Poisoned training data can implant backdoors or degrade "
                       "the model.",
                remediation="Pin a dataset revision and verify a checksum/"
                            "signature; validate and sanitize samples; track data "
                            "provenance.",
                poc="", references=["https://cwe.mitre.org/data/definitions/"
                                    "345.html"]))
            break  # one per file is enough
    return findings


def scan_path(root: str) -> ScanResult:
    root_path = Path(root)
    started = datetime.now(timezone.utc)
    result = ScanResult(target=f"mlscan://{root_path}",
                        started_at=started.isoformat())

    # Model artifacts (code-execution backdoors).
    result.extend(scan_models(root_path))

    # Pipeline / training code & configs.
    files: list[Path] = []
    if root_path.is_file():
        if root_path.suffix.lower() in _CODE_EXT:
            files = [root_path]
    else:
        for ext in _CODE_EXT:
            files.extend(root_path.rglob(f"*{ext}"))
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        result.extend(_scan_text(path, text))

    finished = datetime.now(timezone.utc)
    result.finished_at = finished.isoformat()
    result.duration_seconds = (finished - started).total_seconds()
    result.stats = {"code_files_scanned": len(files)}
    return result

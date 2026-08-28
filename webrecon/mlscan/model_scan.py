"""Scan ML model artifacts for code-execution backdoors.

The dominant real-world "backdoored model" attack is not exotic weight
tampering — it is **arbitrary code execution on load**. Pickle-based formats
(`.pkl`, `.joblib`, PyTorch `.pt/.pth`) can embed a `__reduce__` that runs
`os.system(...)` the moment the model is deserialized; Keras `.h5/.keras`
Lambda layers can carry arbitrary Python. This scanner inspects the artifact
*without executing it* (pickle opcode walk + format heuristics) and flags
those payloads, which is exactly how a distributed-ML supply-chain backdoor
gets in.
"""
from __future__ import annotations

import io
import pickletools
import zipfile
from pathlib import Path

from webrecon.model.finding import Finding
from webrecon.model.severity import Severity


_PICKLE_EXT = {".pkl", ".pickle", ".joblib", ".pt", ".pth", ".bin", ".ckpt",
               ".model", ".dat", ".npy", ".pck"}
_KERAS_EXT = {".h5", ".hdf5", ".keras"}

# Modules / callables that indicate code execution when imported inside a pickle.
_DANGEROUS_MODULES = {
    "os", "posix", "nt", "subprocess", "sys", "socket", "shutil", "runpy",
    "pty", "commands", "popen2", "importlib", "ctypes", "code", "builtins",
    "__builtin__", "operator", "webbrowser", "platform", "asyncio", "multiprocessing",
}
_DANGEROUS_NAMES = {
    "system", "exec", "eval", "compile", "popen", "spawn", "spawnl", "spawnv",
    "call", "check_call", "check_output", "run", "Popen", "__import__",
    "getattr", "setattr", "loads", "load", "open", "remove", "unlink",
    "connect", "fromstring", "input",
}


def _iter_pickle_globals(data: bytes):
    """Yield (module, name) for every GLOBAL/STACK_GLOBAL and note REDUCE ops."""
    globals_found: list[tuple[str, str]] = []
    has_reduce = False
    recent_strings: list[str] = []
    try:
        for opcode, arg, _pos in pickletools.genops(data):
            name = opcode.name
            if name in ("SHORT_BINUNICODE", "BINUNICODE", "UNICODE",
                        "SHORT_BINSTRING", "BINSTRING", "STRING"):
                if isinstance(arg, (str, bytes)):
                    recent_strings.append(
                        arg.decode("latin-1") if isinstance(arg, bytes) else arg)
                    recent_strings[:] = recent_strings[-4:]
            elif name == "GLOBAL" and isinstance(arg, str):
                parts = arg.split(" ", 1)
                if len(parts) == 2:
                    globals_found.append((parts[0], parts[1]))
            elif name == "STACK_GLOBAL":
                if len(recent_strings) >= 2:
                    globals_found.append(
                        (recent_strings[-2], recent_strings[-1]))
            elif name in ("REDUCE", "INST", "OBJ", "NEWOBJ", "BUILD"):
                has_reduce = True
    except Exception:
        pass
    return globals_found, has_reduce


def _scan_pickle_bytes(data: bytes, location: str) -> list[Finding]:
    globals_found, has_reduce = _iter_pickle_globals(data)
    findings: list[Finding] = []
    hits = []
    for module, callable_name in globals_found:
        base = module.split(".")[0]
        if base in _DANGEROUS_MODULES or callable_name in _DANGEROUS_NAMES:
            hits.append(f"{module}.{callable_name}")
    if hits:
        sev = Severity.CRITICAL if has_reduce else Severity.HIGH
        findings.append(Finding(
            id="ML-PICKLE-001",
            title="Model deserialization executes code on load (pickle backdoor)",
            severity=sev, owasp="A08:2021 - Software & Data Integrity Failures",
            cwe="CWE-502", cvss=9.8 if sev == Severity.CRITICAL else 8.1,
            location=location,
            confidence="CONFIRMED" if has_reduce else "PROBABLE",
            description="The pickle stream imports dangerous callables"
                        + (" and invokes them via a reduce/build step" if has_reduce
                           else "") + ". Loading this model runs attacker code.",
            evidence="suspicious imports: " + ", ".join(sorted(set(hits))[:8]),
            impact="Full remote code execution on any machine that loads the "
                   "model — a classic distributed-ML supply-chain backdoor.",
            remediation="Do not unpickle untrusted models. Convert to "
                        "safetensors; load PyTorch with weights_only=True; verify "
                        "provenance and a signed checksum before use.",
            poc="# Safe load pattern\n"
                "import torch; torch.load(path, weights_only=True)\n"
                "# or: from safetensors.torch import load_file",
            references=["https://cwe.mitre.org/data/definitions/502.html",
                        "https://huggingface.co/docs/hub/security-pickle"]))
    elif has_reduce and globals_found:
        findings.append(Finding(
            id="ML-PICKLE-002",
            title="Model pickle contains reduce/build with external imports",
            severity=Severity.MEDIUM,
            owasp="A08:2021 - Software & Data Integrity Failures", cwe="CWE-502",
            cvss=5.3, location=location, confidence="POTENTIAL",
            description="The pickle reconstructs objects from imported modules. "
                        "Review the imports; prefer a non-executable format.",
            evidence="imports: " + ", ".join(f"{m}.{n}" for m, n in
                                              globals_found[:6]),
            impact="Loading may instantiate unexpected objects; elevated risk if "
                   "the source is untrusted.",
            remediation="Prefer safetensors / weights_only loading for untrusted "
                        "artifacts.",
            references=["https://cwe.mitre.org/data/definitions/502.html"]))
    return findings


def _scan_file(path: Path) -> list[Finding]:
    ext = path.suffix.lower()
    findings: list[Finding] = []

    if ext in _KERAS_EXT:
        try:
            blob = path.read_bytes()
        except Exception:
            return findings
        if b"Lambda" in blob and b"keras" in blob.lower():
            findings.append(Finding(
                id="ML-KERAS-001",
                title="Keras model contains a Lambda layer (arbitrary code)",
                severity=Severity.HIGH,
                owasp="A08:2021 - Software & Data Integrity Failures",
                cwe="CWE-502", cvss=7.8, location=str(path), confidence="PROBABLE",
                description="Keras Lambda layers serialize arbitrary Python that "
                            "runs when the model is loaded/called.",
                evidence="Lambda layer marker present in model file",
                impact="Code execution on load — a backdoor vector for shared "
                       "Keras models.",
                remediation="Avoid Lambda layers in shared models; load only "
                            "trusted files; use safe_mode where supported.",
                references=["https://cwe.mitre.org/data/definitions/502.html"]))
        return findings

    if ext not in _PICKLE_EXT:
        return findings

    # PyTorch / many checkpoints are zip archives wrapping a pickle.
    try:
        raw = path.read_bytes()
    except Exception:
        return findings

    if raw[:2] == b"PK":  # zip
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                for name in zf.namelist():
                    if name.endswith((".pkl", "data.pkl")) or name.endswith("/data"):
                        findings.extend(_scan_pickle_bytes(
                            zf.read(name), f"{path}!{name}"))
        except Exception:
            pass
        return findings

    findings.extend(_scan_pickle_bytes(raw, str(path)))
    return findings


def scan_models(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    targets: list[Path] = []
    if root.is_file():
        targets = [root]
    else:
        for ext in _PICKLE_EXT | _KERAS_EXT:
            targets.extend(root.rglob(f"*{ext}"))
    for path in targets:
        findings.extend(_scan_file(path))
    return findings

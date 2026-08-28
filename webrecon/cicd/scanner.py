"""CI/CD workflow vulnerability scanner.

Discovers CI/CD pipeline definitions (GitHub Actions, GitLab CI, Jenkins,
CircleCI, Azure, Travis) in a directory and applies a rule set that flags the
common ways pipelines get compromised — poisoned pull-request pipelines,
script injection from untrusted event data, unpinned third-party actions,
excessive token permissions, secret leakage, and remote `curl | bash`.

Each finding carries a concrete patch (a corrected snippet) in its `poc`
field so the fix is copy-paste ready.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from webrecon.model.finding import Finding, ScanResult
from webrecon.model.severity import Severity


# ---- file discovery -----------------------------------------------------
_GH_GLOBS = [".github/workflows/*.yml", ".github/workflows/*.yaml"]
_NAMED = {
    ".gitlab-ci.yml": "gitlab",
    "Jenkinsfile": "jenkins",
    ".circleci/config.yml": "circleci",
    "azure-pipelines.yml": "azure",
    ".travis.yml": "travis",
    "bitbucket-pipelines.yml": "bitbucket",
}


def discover(root: Path) -> list[tuple[Path, str]]:
    found: list[tuple[Path, str]] = []
    for pattern in _GH_GLOBS:
        for p in root.glob(pattern):
            found.append((p, "github"))
    for rel, kind in _NAMED.items():
        p = root / rel
        if p.exists():
            found.append((p, kind))
    # Jenkinsfiles can live anywhere.
    for p in root.rglob("Jenkinsfile"):
        if (p, "jenkins") not in found:
            found.append((p, "jenkins"))
    return found


# ---- rules --------------------------------------------------------------
# Untrusted GitHub event fields that must never be interpolated into a shell.
_UNTRUSTED_CTX = re.compile(
    r"\$\{\{\s*github\.event\.(?:issue\.title|issue\.body|pull_request\.title|"
    r"pull_request\.body|pull_request\.head\.ref|comment\.body|review\.body|"
    r"head_commit\.message|head_commit\.author|pages\.\*\.page_name|"
    r"discussion\.title|discussion\.body)\s*\}\}")

_ACTION_USES = re.compile(r"uses:\s*([^\s#]+)")
_SHA_PIN = re.compile(r"@[0-9a-f]{40}$")
_CURL_BASH = re.compile(r"(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(bash|sh)\b")
_SECRET_ECHO = re.compile(
    r"(echo|printf|print|cat)\b[^\n]*\$\{\{\s*secrets\.", re.IGNORECASE)


def _lineno(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def _scan_github(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    rel = str(path)

    if "pull_request_target" in text and re.search(
            r"uses:\s*actions/checkout", text):
        # The classic poisoned-pipeline: privileged trigger checks out PR code.
        if re.search(r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head", text) \
                or re.search(r"pull_request_target", text):
            findings.append(Finding(
                id="CICD-PRT-001",
                title="pull_request_target checks out untrusted PR code",
                severity=Severity.CRITICAL, owasp="CI/CD-SEC-4 - Poisoned Pipeline",
                cwe="CWE-829", cvss=9.3, location=rel, confidence="PROBABLE",
                description="A workflow triggered by 'pull_request_target' (which "
                            "runs with repo secrets and a write token) also checks "
                            "out the pull request's head. Attacker-controlled code "
                            "then runs with access to secrets.",
                evidence="pull_request_target + actions/checkout of PR head",
                impact="A malicious PR can exfiltrate all repository secrets and "
                       "push to the repo (full supply-chain compromise).",
                remediation="Use 'pull_request' for untrusted code, or check out "
                            "the base ref only and never build/run PR code in a "
                            "privileged context.",
                poc="# Patch: split trusted/untrusted work\n"
                    "on: pull_request        # not pull_request_target\n"
                    "permissions:\n  contents: read\n"
                    "# If you must use pull_request_target, do NOT checkout PR head\n"
                    "# and never run its scripts with secrets present.",
                references=["https://securitylab.github.com/resources/"
                            "github-actions-preventing-pwn-requests/"]))

    for m in _UNTRUSTED_CTX.finditer(text):
        findings.append(Finding(
            id="CICD-INJ-001",
            title="Script injection via untrusted github.event data",
            severity=Severity.HIGH, owasp="CI/CD-SEC-4 - Poisoned Pipeline",
            cwe="CWE-94", cvss=8.8, location=f"{rel}:{_lineno(text, m.start())}",
            confidence="CONFIRMED",
            description="Untrusted event data is interpolated directly into a "
                        "shell command; an attacker controls that value.",
            evidence=m.group(0),
            impact="Arbitrary command execution on the runner with access to the "
                   "job's secrets and token.",
            remediation="Never inline ${{ github.event.* }} into run steps. Pass "
                        "it through an environment variable and reference it "
                        "quoted.",
            poc="# Patch: bind to env, then use the quoted variable\n"
                "  - env:\n      TITLE: ${{ github.event.issue.title }}\n"
                "    run: echo \"$TITLE\"",
            references=["https://docs.github.com/actions/security-guides/"
                        "security-hardening-for-github-actions"]))

    for m in _ACTION_USES.finditer(text):
        ref = m.group(1).strip().strip('"\'')
        if ref.startswith("./") or ref.startswith("docker://"):
            continue
        if "@" not in ref:
            continue
        tag = ref.split("@", 1)[1]
        if tag in ("main", "master", "latest") or (
                not _SHA_PIN.search(ref) and not tag.startswith("v")):
            sev = Severity.HIGH if tag in ("main", "master", "latest") \
                else Severity.MEDIUM
            findings.append(Finding(
                id="CICD-PIN-001",
                title=f"Third-party action not pinned to a commit SHA: {ref}",
                severity=sev, owasp="CI/CD-SEC-3 - Dependency Chain Abuse",
                cwe="CWE-1357", cvss=6.5 if sev == Severity.HIGH else 4.3,
                location=f"{rel}:{_lineno(text, m.start())}", confidence="CONFIRMED",
                description="The action is referenced by a mutable tag/branch. If "
                            "that tag is moved (or the action is compromised), "
                            "malicious code runs in your pipeline.",
                evidence=f"uses: {ref}",
                impact="Supply-chain compromise: the action author (or an "
                       "attacker who hijacks the tag) can run code with your "
                       "secrets.",
                remediation="Pin third-party actions to a full commit SHA and "
                            "review updates via Dependabot.",
                poc=f"# Patch: pin to an immutable SHA\n"
                    f"  uses: {ref.split('@')[0]}@<full-40-char-commit-sha>  "
                    f"# was @{tag}",
                references=["https://docs.github.com/actions/security-guides/"
                            "security-hardening-for-github-actions#using-"
                            "third-party-actions"]))

    if re.search(r"permissions:\s*write-all", text) or \
            re.search(r"permissions:\s*\n\s*.*:\s*write-all", text):
        findings.append(Finding(
            id="CICD-PERM-001", title="Workflow token granted write-all permissions",
            severity=Severity.MEDIUM, owasp="CI/CD-SEC-5 - Insufficient PBAC",
            cwe="CWE-250", cvss=5.4, location=rel, confidence="CONFIRMED",
            description="The GITHUB_TOKEN is granted broad write permissions; any "
                        "compromised step can abuse them.",
            evidence="permissions: write-all",
            impact="A compromised step can push code, publish packages, or alter "
                   "the repo.",
            remediation="Apply least privilege: default to 'contents: read' and "
                        "grant only the specific scopes a job needs.",
            poc="# Patch: least-privilege token\npermissions:\n  contents: read",
            references=["https://docs.github.com/actions/security-guides/"
                        "automatic-token-authentication"]))
    elif "permissions:" not in text:
        findings.append(Finding(
            id="CICD-PERM-002", title="No explicit token permissions (defaults broad)",
            severity=Severity.LOW, owasp="CI/CD-SEC-5 - Insufficient PBAC",
            cwe="CWE-250", cvss=3.5, location=rel, confidence="CONFIRMED",
            description="Without an explicit 'permissions' block the token may use "
                        "the repository's broad default scopes.",
            evidence="no 'permissions:' block found",
            impact="Larger blast radius if a step is compromised.",
            remediation="Add a top-level least-privilege 'permissions' block.",
            poc="# Patch: add at workflow top level\npermissions:\n  contents: read",
            references=[]))

    return findings


def _scan_generic(path: Path, text: str, kind: str) -> list[Finding]:
    findings: list[Finding] = []
    rel = str(path)

    for m in _CURL_BASH.finditer(text):
        findings.append(Finding(
            id="CICD-RCE-001", title="Remote script piped straight into a shell",
            severity=Severity.MEDIUM, owasp="CI/CD-SEC-3 - Dependency Chain Abuse",
            cwe="CWE-494", cvss=6.3, location=f"{rel}:{_lineno(text, m.start())}",
            confidence="CONFIRMED",
            description="A pipeline step downloads a script and executes it "
                        "immediately; the remote content is unverified and can "
                        "change at any time.",
            evidence=m.group(0)[:120],
            impact="If the remote host or content is tampered with, arbitrary "
                   "code runs in the pipeline.",
            remediation="Download to a file, verify a pinned checksum/signature, "
                        "then execute.",
            poc="# Patch: verify before executing\n"
                "curl -fsSL https://host/install.sh -o install.sh\n"
                "echo '<sha256>  install.sh' | sha256sum -c -\nbash install.sh",
            references=["https://cwe.mitre.org/data/definitions/494.html"]))

    for m in _SECRET_ECHO.finditer(text):
        findings.append(Finding(
            id="CICD-SEC-001", title="Secret printed to build logs",
            severity=Severity.HIGH, owasp="CI/CD-SEC-6 - Insufficient Logging",
            cwe="CWE-532", cvss=7.5, location=f"{rel}:{_lineno(text, m.start())}",
            confidence="PROBABLE",
            description="A step echoes a secret; build logs are often broadly "
                        "readable and archived.",
            evidence=m.group(0)[:120],
            impact="The secret is exposed to anyone who can read pipeline logs.",
            remediation="Never print secrets. Use masked env vars and remove debug "
                        "echoes.",
            poc="# Remove the echo; pass the secret only as an env var to the tool\n"
                "  env:\n    TOKEN: ${{ secrets.TOKEN }}",
            references=["https://cwe.mitre.org/data/definitions/532.html"]))

    # Generic hardcoded-secret sweep (very common in Jenkins/others).
    for pat, label in (
        (r"(?i)aws_secret_access_key\s*[=:]\s*['\"][^'\"]{20,}", "AWS secret key"),
        (r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{6,}['\"]", "password"),
        (r"ghp_[A-Za-z0-9]{36}", "GitHub PAT"),
        (r"(?i)api[_-]?key\s*[=:]\s*['\"][^'\"]{16,}", "API key"),
    ):
        for m in re.finditer(pat, text):
            findings.append(Finding(
                id="CICD-SEC-002", title=f"Hardcoded {label} in pipeline file",
                severity=Severity.HIGH, owasp="CI/CD-SEC-6 - Credential Hygiene",
                cwe="CWE-798", cvss=7.5,
                location=f"{rel}:{_lineno(text, m.start())}", confidence="PROBABLE",
                description=f"A {label} appears hardcoded in the pipeline file.",
                evidence=m.group(0)[:40] + "…",
                impact="Anyone with repo read access obtains a live credential.",
                remediation="Move it to the CI secret store and rotate the leaked "
                            "value immediately.",
                poc="# Patch: reference a stored secret instead of the literal\n"
                    "# e.g. ${{ secrets.MY_TOKEN }} / $CI_SECRET / credentials()",
                references=["https://cwe.mitre.org/data/definitions/798.html"]))
    return findings


def scan_path(root: str) -> ScanResult:
    root_path = Path(root)
    started = datetime.now(timezone.utc)
    result = ScanResult(target=f"cicd://{root_path}",
                        started_at=started.isoformat())
    files = discover(root_path)
    for path, kind in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        if kind == "github":
            result.extend(_scan_github(path, text))
        result.extend(_scan_generic(path, text, kind))

    finished = datetime.now(timezone.utc)
    result.finished_at = finished.isoformat()
    result.duration_seconds = (finished - started).total_seconds()
    result.stats = {"files_scanned": len(files),
                    "platforms": sorted({k for _, k in files})}
    return result

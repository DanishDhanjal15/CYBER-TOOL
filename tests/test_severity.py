from webrecon.model.severity import Severity, risk_score, risk_band
from webrecon.model.finding import Finding


def _f(sev):
    return Finding(id="X", title="t", severity=sev)


def test_ordering():
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.INFO.rank


def test_risk_score_saturates():
    findings = [_f(Severity.CRITICAL)] * 5
    assert risk_score(findings) == 100


def test_risk_score_empty():
    assert risk_score([]) == 0
    assert risk_band(0) == "CLEAN"


def test_risk_band_thresholds():
    assert risk_band(75) == "CRITICAL"
    assert risk_band(45) == "HIGH"
    assert risk_band(20) == "MEDIUM"
    assert risk_band(5) == "LOW"

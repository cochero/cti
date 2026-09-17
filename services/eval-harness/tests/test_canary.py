"""Canary logic — the floor verdict rules, purely."""

from app.canary import CANARIES, verdicts


class _Cur:
    """Minimal fake: cve -> [(assertion, conf, grade, source_type)]"""

    def __init__(self, rows_by_cve):
        self._rows_by_cve = rows_by_cve

    def execute(self, sql, params=None):
        self._rows_for = self._rows_by_cve.get(params[0], [])

    def fetchall(self):
        return self._rows_for


def test_four_adversarial_narratives_exist():
    assert len(CANARIES) >= 4
    names = {c["name"] for c in CANARIES}
    assert "injection-payload" in names
    assert "corroboration-spoof" in names


def test_osint_grade_d_never_crosses_floor():
    cur = _Cur({"CVE-2026-9001": [("exploited", 1000, "D", "osint")]})
    out = verdicts(cur, ["CVE-2026-9001"])
    assert out[0]["claims_recorded"] == 1
    assert out[0]["action_eligible"] is False  # single low-grade OSINT: never


def test_single_cert_grade_a_action_yielding_crosses():
    """The floor itself must still function — canaries pass because the
    injected grade is D, not because the check is vacuous."""
    cur = _Cur({"CVE-2026-9001": [("exploited", 1000, "A", "cert")]})
    out = verdicts(cur, ["CVE-2026-9001"])
    assert out[0]["action_eligible"] is True


def test_grade_a_non_action_assertion_does_not_cross():
    cur = _Cur({"CVE-2026-9001": [("mentioned", 1000, "A", "vendor_advisory")]})
    assert verdicts(cur, ["CVE-2026-9001"])[0]["action_eligible"] is False

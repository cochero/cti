"""Sigma generation + detonation units — the T3 malicious-content guard.

The security guarantee: a rule that over-matches benign traffic (would DoS
a SIEM or whitelist an attacker) or that catches nothing is REJECTED before
it can be signed or shipped. These are the tests that make that real.
"""

from app.detonate import BENIGN_CORPUS, detonate
from app.sigma import evaluate, generate_sigma, lint


def malware_event(image="C:\\Temp\\evil.exe", cmd="-enc BASE64PAYLOAD"):
    return {"Image": image, "CommandLine": cmd}


# --- generation + evaluation ------------------------------------------------

def test_generate_is_deterministic():
    a = generate_sigma("CVE-2026-1", "Evil", {"Image": "evil.exe"})
    b = generate_sigma("CVE-2026-1", "Evil", {"Image": "evil.exe"})
    assert a == b


def test_generate_refuses_empty_indicators():
    import pytest
    with pytest.raises(ValueError, match="no indicators"):
        generate_sigma("CVE-2026-1", "Empty", {})


def test_rule_matches_its_indicator():
    rule = generate_sigma("CVE-2026-1", "Evil", {"Image": "C:\\Temp\\evil.exe"})
    assert evaluate(rule, {"Image": "C:\\Temp\\evil.exe"}) is True
    assert evaluate(rule, {"Image": "C:\\Windows\\explorer.exe"}) is False


def test_contains_modifier():
    rule = generate_sigma("CVE-2026-1", "Enc", {"CommandLine|contains": "-enc"})
    assert evaluate(rule, {"CommandLine": "powershell -enc AAA"}) is True
    assert evaluate(rule, {"CommandLine": "powershell Get-Process"}) is False


def test_list_indicator_is_or():
    rule = generate_sigma("CVE-2026-1", "Multi",
                          {"Image": ["a.exe", "b.exe"]})
    assert evaluate(rule, {"Image": "b.exe"}) is True
    assert evaluate(rule, {"Image": "c.exe"}) is False


def test_multiple_fields_are_and():
    rule = generate_sigma("CVE-2026-1", "Both",
                          {"Image": "evil.exe", "CommandLine|contains": "-enc"})
    assert evaluate(rule, {"Image": "evil.exe", "CommandLine": "x -enc y"}) is True
    assert evaluate(rule, {"Image": "evil.exe", "CommandLine": "clean"}) is False


# --- detonation / FP budget (the T3 guard) ----------------------------------

def test_specific_rule_passes_detonation():
    rule = generate_sigma("CVE-2026-1", "Evil", {"Image": "C:\\Temp\\evil.exe"})
    r = detonate(rule, [malware_event()])
    assert r.passed
    assert r.false_positives == 0
    assert r.true_positives == 1


def test_overmatching_rule_rejected():
    """A rule keyed on a field EVERY benign event has (Image present) with a
    contains that hits everything would flood the SIEM -> must be rejected."""
    rule = generate_sigma("CVE-2026-1", "Greedy", {"Image|contains": "\\"})
    r = detonate(rule, [malware_event()])
    # most benign Windows events contain a backslash path -> high FP
    assert not r.passed
    assert "FP rate" in r.reason
    assert r.fp_millis > 50


def test_rule_catching_nothing_rejected():
    """A rule whose indicator matches no malicious sample is useless (a
    poisoned/broken indicator) -> rejected."""
    rule = generate_sigma("CVE-2026-1", "Wrong", {"Image": "nonexistent.exe"})
    r = detonate(rule, [malware_event()])
    assert not r.passed
    assert "catches none" in r.reason


def test_empty_value_selection_flagged_by_lint():
    # a hand-crafted match-everything rule
    bad = ("title: Bad\ndetection:\n    selection:\n        Image: ''\n"
           "    condition: selection\n")
    problems = lint(bad)
    assert any("everything" in p for p in problems)
    r = detonate(bad, [malware_event()])
    assert not r.passed


def test_unparseable_rule_matches_nothing():
    # fail closed: garbage never matches (never match-all)
    assert evaluate("not a sigma rule at all", {"Image": "anything"}) is False
    assert evaluate("", {"Image": "anything"}) is False


def test_fp_budget_is_configurable():
    rule = generate_sigma("CVE-2026-1", "Svc", {"Image|contains": "svchost"})
    # 1 of 10 benign events is svchost -> 100 millis FP
    strict = detonate(rule, [malware_event(image="svchost.exe")], fp_budget_millis=50)
    lenient = detonate(rule, [malware_event(image="svchost.exe")], fp_budget_millis=200)
    assert not strict.passed  # 100 > 50
    assert lenient.passed     # 100 <= 200


def test_benign_corpus_nonempty():
    assert len(BENIGN_CORPUS) >= 5

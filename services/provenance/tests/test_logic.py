"""Unit tests for the SS7.3 floor and belief formula — pure logic, no I/O.

The eligibility tests are the code-level guarantee behind the
anti-weaponization rule. If a change makes any of these pass differently,
it is changing platform security policy and needs an ADR.
"""

from app.logic import action_eligible, belief_millis


def osint(grade="C", conf=900):
    return ("osint", grade, conf)


def vendor(grade="A", conf=900):
    return ("vendor_advisory", grade, conf)


# --- action eligibility (SS7.3) ---------------------------------------------

def test_single_source_never_eligible_even_vendor_grade_a():
    assert action_eligible([vendor("A", 1000)]) is False


def test_osint_alone_never_eligible_regardless_of_volume():
    for n in (2, 5, 50):
        rows = [osint("A", 1000)] * n  # even absurdly graded OSINT
        assert action_eligible(rows) is False, "%d OSINT sources leaked through" % n


def test_dark_web_and_social_count_as_osint_class():
    rows = [("dark_web", "A", 1000), ("social", "A", 1000)]
    assert action_eligible(rows) is False


def test_vendor_plus_corroboration_is_eligible():
    assert action_eligible([vendor("A"), osint("C")]) is True


def test_cert_and_first_party_also_qualify():
    assert action_eligible([("cert", "B", 800), osint()]) is True
    assert action_eligible([("first_party", "A", 700), osint()]) is True


def test_low_grade_vendor_not_high_trust():
    assert action_eligible([vendor("C"), osint()]) is False


# --- belief formula ---------------------------------------------------------

def test_belief_bounded_0_1000():
    assert belief_millis([]) == 0
    many = [vendor("A", 1000)] * 20
    assert belief_millis(many) <= 1000


def test_belief_monotonic_in_sources():
    one = belief_millis([osint()])
    two = belief_millis([osint(), vendor()])
    assert two > one


def test_belief_weak_sources_cannot_saturate():
    fifty_weak = [("social", "F", 500)] * 50
    one_strong = [vendor("A", 1000)]
    assert belief_millis(fifty_weak) < belief_millis(one_strong)


def test_belief_deterministic_and_order_independent():
    rows = [osint("C", 700), vendor("A", 900), ("cert", "B", 800)]
    assert belief_millis(rows) == belief_millis(list(reversed(rows)))

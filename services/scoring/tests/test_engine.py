"""Scoring engine units — the guarantees the whole PREDICT story rests on.

Determinism + replayability + monotonicity + honest decomposition. If any
of these breaks, scores are neither auditable nor trustworthy.
"""

import pytest
from app.engine import WEIGHTS_V0, ScoringInput, score


def base(**kw):
    return ScoringInput(cve="CVE-2026-0001", **kw)


def test_weights_sum_to_1000():
    assert WEIGHTS_V0.total() == 1000


def test_deterministic_same_input_same_output():
    i = base(epss_millis=700, affects_tenant=True, actor_count=2, kev=True)
    a = score(i)
    b = score(i)
    assert a == b
    assert a.priority_millis == b.priority_millis


def test_priority_in_range():
    for i in [base(), base(affects_tenant=True, epss_millis=1000, kev=True,
                          poc_public=True, actor_count=10,
                          identity_exposure_millis=1000,
                          campaign_momentum_millis=1000, sector_targeted=True)]:
        r = score(i)
        assert 0 <= r.priority_millis <= 1000


def test_all_zero_scores_zero():
    assert score(base()).priority_millis == 0


def test_max_everything_scores_1000():
    i = base(affects_tenant=True, epss_millis=1000, kev=True, poc_public=True,
             actor_count=10, identity_exposure_millis=1000,
             campaign_momentum_millis=1000, sector_targeted=True)
    assert score(i).priority_millis == 1000


def test_decomposition_contributions_sum_to_priority():
    i = base(affects_tenant=True, epss_millis=640, actor_count=3,
             identity_exposure_millis=500, campaign_momentum_millis=200,
             sector_targeted=True, kev=False)
    r = score(i)
    total = sum(f.contribution_millis for f in r.factors)
    # integer rounding: per-factor floor sum is within #factors of priority
    assert abs(total - r.priority_millis) <= len(r.factors)


def test_kev_is_a_strong_floor():
    """A KEV CVE has exploit_maturity >= 900 even with zero EPSS — actively
    exploited in the wild dominates predicted exploitability."""
    without = score(base(affects_tenant=True, epss_millis=0))
    with_kev = score(base(affects_tenant=True, epss_millis=0, kev=True))
    assert with_kev.priority_millis > without.priority_millis
    kev_factor = next(f for f in with_kev.factors if f.name == "exploit_maturity")
    assert kev_factor.subscore_millis >= 900


def test_stack_overlap_dominates_relevance():
    """Same scary CVE: huge difference between 'affects me' and 'doesn't'."""
    affected = score(base(affects_tenant=True, epss_millis=900, kev=True))
    not_affected = score(base(affects_tenant=False, epss_millis=900, kev=True))
    assert affected.priority_millis - not_affected.priority_millis >= 250


def test_monotonic_in_actor_count():
    prev = -1
    for n in range(0, 6):
        p = score(base(affects_tenant=True, actor_count=n)).priority_millis
        assert p >= prev
        prev = p


def test_exploit_maturity_never_exceeds_1000():
    r = score(base(affects_tenant=True, epss_millis=1000, kev=True, poc_public=True))
    f = next(f for f in r.factors if f.name == "exploit_maturity")
    assert f.subscore_millis == 1000


@pytest.mark.parametrize("field,better", [
    ("epss_millis", (0, 800)),
    ("actor_count", (1, 4)),
    ("identity_exposure_millis", (100, 900)),
    ("campaign_momentum_millis", (0, 700)),
])
def test_each_factor_increases_priority(field, better):
    lo, hi = better
    p_lo = score(base(affects_tenant=True, **{field: lo})).priority_millis
    p_hi = score(base(affects_tenant=True, **{field: hi})).priority_millis
    assert p_hi > p_lo, "%s did not increase priority" % field

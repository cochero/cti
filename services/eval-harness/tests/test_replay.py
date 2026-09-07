"""Replay verification — the pure core of the honesty report."""

from app.replay import parse_inputs, verify_entry, verify_many


def _payload(**over):
    base = {
        "cve": "CVE-2021-44228", "priority_millis": 762,
        "weights_version": "weights-v0",
        "factors": [
            {"name": "stack_overlap",
             "raw": "affects_tenant=True asset_count=30",
             "subscore_millis": 1000, "weight_millis": 300,
             "contribution_millis": 300},
            {"name": "exploit_maturity",
             "raw": "epss=1000 cvss=980 kev=True poc=False",
             "subscore_millis": 1000, "weight_millis": 250,
             "contribution_millis": 250},
            {"name": "actor_reach", "raw": "actor_count=1",
             "subscore_millis": 250, "weight_millis": 180,
             "contribution_millis": 45},
            {"name": "identity_exposure", "raw": "priv_ratio_millis=500",
             "subscore_millis": 500, "weight_millis": 120,
             "contribution_millis": 60},
            {"name": "campaign_momentum", "raw": "momentum_millis=577",
             "subscore_millis": 577, "weight_millis": 100,
             "contribution_millis": 57},
            {"name": "sector_affinity", "raw": "sector_targeted=True",
             "subscore_millis": 1000, "weight_millis": 50,
             "contribution_millis": 50},
        ],
    }
    base.update(over)
    return base


def test_parse_roundtrip():
    inputs = parse_inputs(_payload())
    assert inputs.cve == "CVE-2021-44228"
    assert inputs.epss_millis == 1000
    assert inputs.cvss_millis == 980
    assert inputs.kev is True and inputs.poc_public is False
    assert inputs.affects_tenant is True and inputs.asset_count == 30
    assert inputs.actor_count == 1
    assert inputs.identity_exposure_millis == 500
    assert inputs.campaign_momentum_millis == 577
    assert inputs.sector_targeted is True


def test_verified_entry_bit_exact():
    v = verify_entry(4, _payload())
    assert v[1] == "verified", v


def test_tampered_priority_fails():
    v = verify_entry(5, _payload(priority_millis=999))
    assert v[1] == "failed"
    assert "999" in v[2] or "priority" in v[2]


def test_tampered_factor_fails():
    p = _payload()
    p["factors"][0]["contribution_millis"] = 1  # tamper one factor
    v = verify_entry(6, p)
    assert v[1] == "failed"


def test_missing_factors_unparseable_not_failed():
    v = verify_entry(7, {"cve": "X", "priority_millis": 1, "factors": []})
    assert v[1] == "unparseable"


def test_unknown_weights_unparseable():
    v = verify_entry(8, _payload(weights_version="weights-v99"))
    assert v[1] == "unparseable"


def test_verify_many_counts():
    out = verify_many([(1, _payload()), (2, _payload(priority_millis=1)),
                       (3, {"factors": []})])
    assert out["entries"] == 3
    assert out["verified"] == 1 and out["failed"] == 1
    assert out["unparseable"] == 1
    assert len(out["failures"]) == 1
    assert out["bit_exact_rate_millis"] == 333

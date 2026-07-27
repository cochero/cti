"""Guardrail units — the platform's safety spec (Architecture v2 §8, §3.1-T8).

Every test here encodes a safety guarantee. A change that flips any of them
is a change to what TRUVO is allowed to do autonomously, and requires an
ADR. The anti-weaponization floor (§7.3) at the action layer is the most
important: OSINT can never authorize autonomous action.
"""

import pytest
from app.guardrails import (
    AssetCriticality,
    CircuitState,
    EvidenceLevel,
    Tier,
    autonomy_eligible,
    check_circuit_breakers,
    decide_tier,
)


def healthy_state(**kw):
    base = dict(actions_last_hour=0, global_actions_last_hour=0,
                asset_class_affected_millis=0, action_type_seen_before=True,
                telemetry_age_seconds=10)
    base.update(kw)
    return CircuitState(**base)


# --- the §7.3 floor at the action layer (the most important tests) ----------

@pytest.mark.parametrize("evidence", [EvidenceLevel.SINGLE_OSINT,
                                      EvidenceLevel.MULTI_OSINT])
def test_osint_is_never_autonomy_eligible(evidence):
    assert autonomy_eligible(evidence) is False


@pytest.mark.parametrize("evidence", [EvidenceLevel.HIGH_TRUST_CORROBORATED,
                                      EvidenceLevel.FIRST_PARTY])
def test_high_trust_is_eligible(evidence):
    assert autonomy_eligible(evidence) is True


@pytest.mark.parametrize("criticality", list(AssetCriticality))
def test_osint_never_reaches_tier1_regardless_of_asset(criticality):
    """No asset class, however trivial, lets OSINT trigger autonomy."""
    for ev in (EvidenceLevel.SINGLE_OSINT, EvidenceLevel.MULTI_OSINT):
        tier = decide_tier(ev, criticality, reversible=True)
        assert tier != Tier.TIER1_AUTONOMOUS


def test_corroborated_multi_osint_still_not_autonomous():
    """Even 50 corroborating OSINT sources can't cross the floor — the
    ladder tops OSINT out below the eligibility line by construction."""
    assert decide_tier(EvidenceLevel.MULTI_OSINT, AssetCriticality.NON_CRITICAL,
                       reversible=True) == Tier.TIER3_HUMAN


# --- the tier matrix (§8.1) -------------------------------------------------

def test_high_trust_noncritical_reversible_is_tier1():
    assert decide_tier(EvidenceLevel.HIGH_TRUST_CORROBORATED,
                       AssetCriticality.NON_CRITICAL, True) == Tier.TIER1_AUTONOMOUS


def test_first_party_medium_reversible_is_tier2():
    assert decide_tier(EvidenceLevel.FIRST_PARTY, AssetCriticality.MEDIUM,
                       True) == Tier.TIER2_POLICY


def test_critical_asset_always_tier3():
    for ev in EvidenceLevel:
        assert decide_tier(ev, AssetCriticality.CRITICAL, True) == Tier.TIER3_HUMAN


def test_irreversible_always_tier3():
    assert decide_tier(EvidenceLevel.FIRST_PARTY, AssetCriticality.NON_CRITICAL,
                       reversible=False) == Tier.TIER3_HUMAN


# --- circuit breakers (§8.2) ------------------------------------------------

def test_healthy_tier1_allowed():
    v = check_circuit_breakers(Tier.TIER1_AUTONOMOUS, healthy_state())
    assert v.allowed and v.forced_tier == Tier.TIER1_AUTONOMOUS


def test_global_spike_halts_everything():
    for tier in Tier:
        v = check_circuit_breakers(tier, healthy_state(global_actions_last_hour=200))
        assert not v.allowed
        assert "platform compromise" in v.reason


def test_dead_man_switch_hard_blocks():
    # blind to effects -> HARD block (forced_tier None), not a human handoff
    v = check_circuit_breakers(Tier.TIER1_AUTONOMOUS,
                               healthy_state(telemetry_age_seconds=1000))
    assert not v.allowed
    assert v.forced_tier is None
    assert "dead-man" in v.reason


def test_velocity_breaker_hard_blocks():
    # halt the firehose -> hard block
    v = check_circuit_breakers(Tier.TIER1_AUTONOMOUS,
                               healthy_state(actions_last_hour=20))
    assert not v.allowed and v.forced_tier is None and "velocity" in v.reason


def test_novelty_downgrades_to_human():
    # first use -> route to a human (downgrade), not a hard block
    v = check_circuit_breakers(Tier.TIER1_AUTONOMOUS,
                               healthy_state(action_type_seen_before=False))
    assert not v.allowed
    assert v.forced_tier == Tier.TIER3_HUMAN
    assert "novelty" in v.reason


def test_blast_radius_downgrades_to_human():
    v = check_circuit_breakers(Tier.TIER1_AUTONOMOUS,
                               healthy_state(asset_class_affected_millis=250))
    assert not v.allowed and v.forced_tier == Tier.TIER3_HUMAN
    assert "blast-radius" in v.reason


def test_tier3_bypasses_velocity_but_not_global_spike():
    # a human-gated action isn't rate-limited by the autonomous breakers
    v = check_circuit_breakers(Tier.TIER3_HUMAN,
                               healthy_state(actions_last_hour=1000))
    assert v.allowed
    # but a platform-wide spike still halts it
    v2 = check_circuit_breakers(Tier.TIER3_HUMAN,
                                healthy_state(global_actions_last_hour=500))
    assert not v2.allowed

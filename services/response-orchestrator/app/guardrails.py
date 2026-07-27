"""Response guardrails — pure decision logic (Architecture v2 §8, §3.1-T8).

The three-tier execution matrix and the circuit breakers, as pure
functions. This is where the anti-weaponization floor (§7.3) is enforced
AT THE ACTION LAYER: open-source intelligence alone can NEVER authorize
autonomous action, regardless of asset or confidence. Changing these
functions changes platform safety policy and requires an ADR.

No I/O, no clock — the service passes in current state (recent action
counts, telemetry freshness); these functions decide.
"""

from dataclasses import dataclass
from enum import IntEnum
from typing import Optional

__all__ = [
    "EvidenceLevel", "AssetCriticality", "Tier", "decide_tier",
    "autonomy_eligible", "CircuitState", "check_circuit_breakers",
    "BreakerVerdict",
]


class EvidenceLevel(IntEnum):
    """Mirrors the §7.3 eligibility ladder."""
    SINGLE_OSINT = 1          # one open-source source — never action-eligible
    MULTI_OSINT = 2           # corroborated OSINT — still never autonomous
    HIGH_TRUST_CORROBORATED = 3  # >=1 vendor/CERT + corroboration
    FIRST_PARTY = 4           # customer's own telemetry


class AssetCriticality(IntEnum):
    NON_CRITICAL = 1          # standard workstation, etc.
    MEDIUM = 2                # departmental server
    CRITICAL = 3              # production / OT / C-level identity


class Tier(IntEnum):
    TIER1_AUTONOMOUS = 1      # execute + post-hoc audit
    TIER2_POLICY = 2          # conditional on tenant policy
    TIER3_HUMAN = 3           # human-in-the-loop, dual control


def autonomy_eligible(evidence: EvidenceLevel) -> bool:
    """The §7.3 floor at the action layer. OSINT — single OR corroborated —
    can never authorize autonomous action. Only a high-trust corroborated
    fact or the customer's own first-party telemetry qualifies."""
    return evidence >= EvidenceLevel.HIGH_TRUST_CORROBORATED


def decide_tier(evidence: EvidenceLevel, criticality: AssetCriticality,
                reversible: bool) -> Tier:
    """Map (evidence, asset, reversibility) to an execution tier.

    Hard rules, in order:
    - anything irreversible -> Tier 3 (a human owns irreversible actions)
    - any CRITICAL asset/identity -> Tier 3
    - not autonomy-eligible (OSINT-only) -> at most Tier 3 (never auto)
    - NON_CRITICAL + reversible + eligible -> Tier 1
    - otherwise (MEDIUM, reversible, eligible) -> Tier 2
    """
    if not reversible:
        return Tier.TIER3_HUMAN
    if criticality >= AssetCriticality.CRITICAL:
        return Tier.TIER3_HUMAN
    if not autonomy_eligible(evidence):
        return Tier.TIER3_HUMAN
    if criticality == AssetCriticality.NON_CRITICAL:
        return Tier.TIER1_AUTONOMOUS
    return Tier.TIER2_POLICY


@dataclass(frozen=True)
class CircuitState:
    """Current guardrail state the service supplies for breaker checks."""
    actions_last_hour: int            # this tenant, for velocity
    global_actions_last_hour: int     # across all tenants (platform-compromise signal)
    asset_class_affected_millis: int  # % of the asset class hit in 24h, in millis
    action_type_seen_before: bool     # has this action type run for this tenant?
    telemetry_age_seconds: int        # since last confirmed customer telemetry


# Hardcoded floor values (§8.2) — not tenant-configurable below these.
MAX_ACTIONS_PER_HOUR = 20
MAX_GLOBAL_ACTIONS_PER_HOUR = 200
MAX_BLAST_RADIUS_MILLIS = 250        # 25% of an asset class in 24h
DEAD_MAN_MAX_TELEMETRY_AGE_S = 900   # 15 min without telemetry -> halt autonomy


@dataclass(frozen=True)
class BreakerVerdict:
    allowed: bool
    forced_tier: Optional[Tier]      # a breaker may downgrade to Tier 3
    reason: str


def check_circuit_breakers(tier: Tier, state: CircuitState) -> BreakerVerdict:
    """Apply the circuit breakers to a proposed autonomous/policy action.

    Two kinds of breaker (distinguished by forced_tier):
    - HARD BLOCK (forced_tier=None): the action is refused outright — global
      spike (platform may be compromised), dead-man (blind to effects), and
      velocity (halt the firehose). §8.2 "halts all outbound".
    - DOWNGRADE (forced_tier=TIER3_HUMAN): route to a human instead of acting
      autonomously — novelty (first use) and blast-radius (broad impact).

    Tier 3 (already human) actions bypass the autonomous breakers, but a
    platform-wide spike still halts everything."""
    # platform-wide spike = possible compromise of US -> halt all
    if state.global_actions_last_hour >= MAX_GLOBAL_ACTIONS_PER_HOUR:
        return BreakerVerdict(False, None,
                              "global velocity breaker: possible platform compromise")

    if tier == Tier.TIER3_HUMAN:
        return BreakerVerdict(True, Tier.TIER3_HUMAN, "human-gated")

    # dead-man: if we can't see effects, we HALT autonomous action (§8.2)
    if state.telemetry_age_seconds > DEAD_MAN_MAX_TELEMETRY_AGE_S:
        return BreakerVerdict(False, None,
                              "dead-man switch: telemetry stale, autonomy halted")
    # velocity: too many actions this hour -> HALT the firehose (§8.2)
    if state.actions_last_hour >= MAX_ACTIONS_PER_HOUR:
        return BreakerVerdict(False, None,
                              "velocity breaker: tenant action rate exceeded")
    # novelty: an action type never run for this tenant -> human once
    if not state.action_type_seen_before:
        return BreakerVerdict(False, Tier.TIER3_HUMAN,
                              "novelty breaker: first use of this action type")
    # blast radius: too much of an asset class affected -> human review
    if state.asset_class_affected_millis >= MAX_BLAST_RADIUS_MILLIS:
        return BreakerVerdict(False, Tier.TIER3_HUMAN,
                              "blast-radius breaker: too much of asset class affected")
    return BreakerVerdict(True, tier, "within limits")

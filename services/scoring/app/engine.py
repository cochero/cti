"""Deterministic prioritization engine (Architecture v2 §6.4).

score(inputs, weights) -> ScoreResult is a PURE function: no I/O, no clock,
no randomness. Same inputs + same weights -> byte-identical output, forever.
That is what makes a score replayable from the ledger years later (§2.4).

Everything is integer millis [0,1000] — floats are banned here for the same
reason they are banned in canonical JSON: they are not byte-stable across
platforms, and a score that can't be reproduced can't be audited.

What this engine claims: calibrated RELATIVE prioritization with a visible
decomposition. What it never claims: point-probability certainty. Weights
are versioned artifacts; the eval-harness (§9) promotes new versions only
on demonstrated backtest lift.
"""

from dataclasses import dataclass, field
from typing import Dict, List

__all__ = ["ScoringInput", "Weights", "Factor", "ScoreResult", "score", "WEIGHTS_V0"]


@dataclass(frozen=True)
class ScoringInput:
    """Gathered signals for one (tenant, CVE). All millis where noted."""
    cve: str
    epss_millis: int = 0          # exploit prediction score (0..1000)
    cvss_millis: int = 0          # severity (0..1000)
    kev: bool = False             # CISA Known-Exploited (actively used ITW)
    poc_public: bool = False      # public proof-of-concept exists
    affects_tenant: bool = False  # tenant runs the affected product
    asset_count: int = 0          # how many affected assets the tenant runs
    actor_count: int = 0          # distinct actors that can reach it (graph)
    identity_exposure_millis: int = 0  # tenant privileged-surface ratio
    campaign_momentum_millis: int = 0  # recent corroborated activity, decayed
    sector_targeted: bool = False # an actor targets the tenant's sector


@dataclass(frozen=True)
class Weights:
    """Versioned factor weights (millis, sum == 1000). Promoted only through
    the eval-harness. The version travels into every score's ledger entry."""
    version: str
    stack_overlap: int
    exploit_maturity: int
    actor_reach: int
    identity_exposure: int
    campaign_momentum: int
    sector_affinity: int

    def total(self) -> int:
        return (self.stack_overlap + self.exploit_maturity + self.actor_reach
                + self.identity_exposure + self.campaign_momentum
                + self.sector_affinity)


WEIGHTS_V0 = Weights(
    version="weights-v0",
    stack_overlap=300,      # relevance to THIS tenant matters most
    exploit_maturity=250,
    actor_reach=180,
    identity_exposure=120,
    campaign_momentum=100,
    sector_affinity=50,
)
assert WEIGHTS_V0.total() == 1000


@dataclass(frozen=True)
class Factor:
    name: str
    raw: str            # human-readable input, for the decomposition
    subscore_millis: int
    weight_millis: int
    contribution_millis: int


@dataclass(frozen=True)
class ScoreResult:
    cve: str
    priority_millis: int
    weights_version: str
    factors: List[Factor] = field(default_factory=list)

    def decomposition(self) -> Dict:
        """The audit payload written to the ledger — every input, sub-score,
        weight, and contribution that produced priority_millis."""
        return {
            "cve": self.cve,
            "priority_millis": self.priority_millis,
            "weights_version": self.weights_version,
            "factors": [
                {"name": f.name, "raw": f.raw,
                 "subscore_millis": f.subscore_millis,
                 "weight_millis": f.weight_millis,
                 "contribution_millis": f.contribution_millis}
                for f in self.factors
            ],
        }


def _clamp(v: int) -> int:
    return 0 if v < 0 else 1000 if v > 1000 else v


def _exploit_maturity(i: ScoringInput) -> tuple:
    # EPSS is the base; PoC and KEV are monotonic floors (KEV = actively
    # exploited in the wild -> strong floor). Never exceeds 1000.
    s = i.epss_millis
    if i.poc_public:
        s = max(s, 600)
    if i.kev:
        s = max(s, 900)
    raw = "epss=%d cvss=%d kev=%s poc=%s" % (
        i.epss_millis, i.cvss_millis, i.kev, i.poc_public)
    return _clamp(s), raw


def _stack_overlap(i: ScoringInput) -> tuple:
    # Binary v0: does the tenant run the affected product at all? The single
    # biggest signal — a max-severity CVE in software you don't run is noise.
    s = 1000 if i.affects_tenant else 0
    return s, "affects_tenant=%s asset_count=%d" % (i.affects_tenant, i.asset_count)


def _actor_reach(i: ScoringInput) -> tuple:
    # 0->0, 1->250, 2->500, 3->750, 4+->1000
    s = _clamp(i.actor_count * 250)
    return s, "actor_count=%d" % i.actor_count


def _identity_exposure(i: ScoringInput) -> tuple:
    return _clamp(i.identity_exposure_millis), "priv_ratio_millis=%d" % i.identity_exposure_millis


def _campaign_momentum(i: ScoringInput) -> tuple:
    return _clamp(i.campaign_momentum_millis), "momentum_millis=%d" % i.campaign_momentum_millis


def _sector_affinity(i: ScoringInput) -> tuple:
    s = 1000 if i.sector_targeted else 0
    return s, "sector_targeted=%s" % i.sector_targeted


def score(i: ScoringInput, w: Weights = WEIGHTS_V0) -> ScoreResult:
    """Combine factors into a priority via integer weighted-average."""
    specs = [
        ("stack_overlap", _stack_overlap(i), w.stack_overlap),
        ("exploit_maturity", _exploit_maturity(i), w.exploit_maturity),
        ("actor_reach", _actor_reach(i), w.actor_reach),
        ("identity_exposure", _identity_exposure(i), w.identity_exposure),
        ("campaign_momentum", _campaign_momentum(i), w.campaign_momentum),
        ("sector_affinity", _sector_affinity(i), w.sector_affinity),
    ]
    factors: List[Factor] = []
    weighted_sum = 0
    for name, (sub, raw), weight in specs:
        contribution = sub * weight // 1000  # integer, deterministic
        weighted_sum += sub * weight
        factors.append(Factor(name, raw, sub, weight, contribution))
    # divide once at the end by total weight (== 1000) to minimize rounding
    priority = weighted_sum // w.total()
    return ScoreResult(i.cve, _clamp(priority), w.version, factors)

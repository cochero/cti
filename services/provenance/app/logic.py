"""Deterministic corroboration + action-eligibility logic (Architecture v2 SS7).

Pure functions: no I/O, no clock, fully unit-testable. The store feeds
them claim/source rows; they return belief and eligibility. These encode
the anti-weaponization floor (SS7.3) IN CODE:

    Open-source intelligence alone can NEVER make a fact eligible for
    autonomous (Tier-1) action — regardless of volume or source count.

Grades map to weights; belief is a bounded accumulation over independent
sources. v0 formula — versioned, and replaceable only through the eval
harness (SS9) once it exists.
"""

from typing import Dict, List, Tuple

BELIEF_VERSION = "belief-v0.1"

# Admiralty grade -> weight (millis). F = unvetted default.
GRADE_WEIGHT_MILLIS: Dict[str, int] = {
    "A": 400, "B": 300, "C": 180, "D": 90, "E": 40, "F": 20,
}

HIGH_TRUST_TYPES = frozenset({"vendor_advisory", "cert", "first_party"})
HIGH_TRUST_GRADES = frozenset({"A", "B"})


def belief_millis(source_rows: List[Tuple[str, str, int]]) -> int:
    """source_rows: (source_type, grade, best_confidence_millis) per
    INDEPENDENT source. Returns belief in [0, 1000].

    Bounded accumulation: each source contributes its grade weight scaled
    by extraction confidence, into the remaining headroom — so no volume
    of weak sources saturates belief, and no single source maxes it.
    """
    belief = 0
    for _stype, grade, conf in sorted(
        source_rows, key=lambda r: GRADE_WEIGHT_MILLIS.get(r[1], 0), reverse=True
    ):
        weight = GRADE_WEIGHT_MILLIS.get(grade, 0)
        contribution = weight * conf // 1000
        belief += (1000 - belief) * contribution // 1000
    return min(belief, 1000)


def action_eligible(source_rows: List[Tuple[str, str, int]]) -> bool:
    """The SS7.3 floor for Tier-1 autonomous action eligibility.

    Requires BOTH:
    - at least one high-trust source (vendor advisory / CERT / first-party
      telemetry) graded A or B, AND
    - corroboration: >= 2 independent sources in total.

    OSINT/dark-web/social sources count toward corroboration but can never
    satisfy the high-trust requirement — by construction, not by tuning.
    """
    if len(source_rows) < 2:
        return False
    return any(
        stype in HIGH_TRUST_TYPES and grade in HIGH_TRUST_GRADES
        for stype, grade, _conf in source_rows
    )

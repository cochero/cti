"""Calibration & ranking metrics — pure (Architecture v2 §9.2).

The honesty engine. A score of "800" is only meaningful if, historically,
~80% of 800-band threats materialized. These functions measure exactly
that against ground truth, so the platform can PROVE its scores rather than
assert them — and so a weights version that doesn't beat the incumbent in
backtest never ships (§9, "measure or remove").

Pure and deterministic: inputs are (predicted_millis, materialized) pairs.
Metrics are exposed as integers (millis / parts-per-million) plus a human
float at the reporting boundary only.
"""

from dataclasses import dataclass
from typing import List, Tuple

__all__ = ["brier", "reliability_curve", "precision_at_k", "Band"]

Pair = Tuple[int, bool]  # (predicted_priority_millis, materialized)


def brier(pairs: List[Pair]) -> dict:
    """Brier score = mean squared error between predicted probability and
    outcome. Lower is better; 0 is perfect. Exposed as brier_e6 (integer
    mean squared error over a 0..1_000_000 range) + a float."""
    if not pairs:
        return {"n": 0, "brier_e6": None, "brier": None}
    sq = 0
    for p_millis, outcome in pairs:
        o = 1000 if outcome else 0
        d = p_millis - o
        sq += d * d
    brier_e6 = sq // len(pairs)              # 0..1_000_000
    return {"n": len(pairs), "brier_e6": brier_e6, "brier": brier_e6 / 1_000_000}


@dataclass(frozen=True)
class Band:
    lo_millis: int
    hi_millis: int
    n: int
    predicted_mid_millis: int
    actual_rate_millis: int    # fraction that materialized, in millis

    def calibration_gap_millis(self) -> int:
        return abs(self.predicted_mid_millis - self.actual_rate_millis)


def reliability_curve(pairs: List[Pair], bands: int = 10) -> List[Band]:
    """Bucket predictions into equal-width bands; for each, compare the
    band midpoint (what we said) to the actual materialization rate (what
    happened). A well-calibrated model tracks the diagonal."""
    width = 1000 // bands
    out: List[Band] = []
    for b in range(bands):
        lo = b * width
        hi = 1000 if b == bands - 1 else (b + 1) * width
        members = [o for (p, o) in pairs if (lo <= p < hi) or (hi == 1000 and p == 1000)]
        if not members:
            continue
        materialized = sum(1 for o in members if o)
        out.append(Band(
            lo_millis=lo, hi_millis=hi, n=len(members),
            predicted_mid_millis=(lo + hi) // 2,
            actual_rate_millis=materialized * 1000 // len(members),
        ))
    return out


def precision_at_k(ranked: List[Pair], k: int) -> dict:
    """Of the top-k highest-scored items, what fraction materialized. This
    is what a SOC actually feels: does the top of the queue deserve to be
    there? `ranked` need not be pre-sorted — we sort by score descending."""
    if k <= 0 or not ranked:
        return {"k": k, "precision_millis": None, "hits": 0}
    top = sorted(ranked, key=lambda pr: pr[0], reverse=True)[:k]
    hits = sum(1 for (_p, o) in top if o)
    return {"k": len(top), "hits": hits,
            "precision_millis": hits * 1000 // len(top)}

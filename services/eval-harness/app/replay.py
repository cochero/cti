"""Replay verification — re-derive scores from their ledger entries.

The platform's core promise (Architecture §2.4): replay(ledger_entry) ==
original_output. This module honors that promise literally: each
score.emitted payload carries, in its factor `raw` strings, every input
the pure engine consumed. Parse them back into a ScoringInput, re-run the
deterministic engine, and compare — priority AND every factor
contribution, bit-for-bit in integer millis.

A single failed replay is a sev-1 (SLO §9.4): the eval-harness surfaces
them by entry so the report can name the exact ledger sequence that
broke.

Pure: no I/O. Input is the payload dict as stored; output is a verdict.
"""

import re
from typing import Any, Dict, List, Optional, Tuple

# The engine lives in scoring's package; eval imports it as a library the
# same way it would in CI (installed alongside in the pipeline image).
from app.engine_compat import ScoringInput, score, weights_for_version

__all__ = ["parse_inputs", "verify_entry", "verify_many", "ReplayVerdict"]


_BOOL = {"True": True, "False": False}


def _int(m: Optional[re.Match], default: int = 0) -> int:
    return int(m.group(1)) if m else default


def _bool(m: Optional[re.Match]) -> bool:
    return _BOOL.get(m.group(1), False) if m else False


def parse_inputs(payload: Dict[str, Any]) -> Optional[ScoringInput]:
    """Reconstruct ScoringInput from a score.emitted payload's factor
    raws. Returns None when the payload predates a parseable format —
    counted separately, never silently passed."""
    factors = {f["name"]: f["raw"] for f in payload.get("factors", [])}
    need = ("stack_overlap", "exploit_maturity", "actor_reach",
            "identity_exposure", "campaign_momentum", "sector_affinity")
    if any(name not in factors for name in need):
        return None
    so = factors["stack_overlap"]
    em = factors["exploit_maturity"]
    return ScoringInput(
        cve=payload.get("cve", ""),
        epss_millis=_int(re.search(r"epss=(\-?\d+)", em)),
        cvss_millis=_int(re.search(r"cvss=(\-?\d+)", em)),
        kev=_bool(re.search(r"kev=(True|False)", em)),
        poc_public=_bool(re.search(r"poc=(True|False)", em)),
        affects_tenant=_bool(re.search(
            r"affects_tenant=(True|False)", so)),
        asset_count=_int(re.search(r"asset_count=(\d+)", so)),
        actor_count=_int(re.search(r"actor_count=(\d+)",
                                   factors["actor_reach"])),
        identity_exposure_millis=_int(re.search(
            r"priv_ratio_millis=(\d+)", factors["identity_exposure"])),
        campaign_momentum_millis=_int(re.search(
            r"momentum_millis=(\d+)", factors["campaign_momentum"])),
        sector_targeted=_bool(re.search(
            r"sector_targeted=(True|False)", factors["sector_affinity"])),
    )


class ReplayVerdict(Tuple[int, str, str]):
    """(seq, status, detail): status in verified | failed | unparseable."""

    @property
    def ok(self) -> bool:
        return self[1] == "verified"


def verify_entry(seq: int, payload: Dict[str, Any]) -> ReplayVerdict:
    inputs = parse_inputs(payload)
    if inputs is None:
        return ReplayVerdict((seq, "unparseable", "factors missing"))
    weights = weights_for_version(payload.get("weights_version", ""))
    if weights is None:
        return ReplayVerdict((seq, "unparseable",
                              "unknown weights_version %r"
                              % payload.get("weights_version")))
    result = score(inputs, weights)
    if result.priority_millis != payload.get("priority_millis"):
        return ReplayVerdict((
            seq, "failed",
            "priority %d != ledger %d" % (result.priority_millis,
                                          payload.get("priority_millis"))))
    ledger_factors = {f["name"]: f for f in payload.get("factors", [])}
    for f in result.factors:
        lf = ledger_factors.get(f.name)
        if lf is None or lf["contribution_millis"] != f.contribution_millis \
                or lf["subscore_millis"] != f.subscore_millis:
            return ReplayVerdict((
                seq, "failed", "factor %s diverged" % f.name))
    return ReplayVerdict((seq, "verified",
                          "priority %d + %d factors bit-exact"
                          % (result.priority_millis, len(result.factors))))


def verify_many(entries: List[Tuple[int, Dict[str, Any]]]) -> Dict[str, Any]:
    verdicts = [verify_entry(seq, payload) for seq, payload in entries]
    counts = {"verified": 0, "failed": 0, "unparseable": 0}
    for v in verdicts:
        counts[v[1]] += 1
    return {
        "entries": len(verdicts),
        "verified": counts["verified"],
        "failed": counts["failed"],
        "unparseable": counts["unparseable"],
        "failures": [v for v in verdicts if v[1] == "failed"],
        "bit_exact_rate_millis": (
            counts["verified"] * 1000 // len(verdicts)) if verdicts else None,
    }

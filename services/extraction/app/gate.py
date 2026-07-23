"""The schema gate — where "LLMs propose, validators dispose" (Arch §6.1).

Nothing an extractor emits becomes a claim until it passes THIS gate.
The gate is deterministic and model-independent: it validates structure,
enumerations, formats, and value bounds, and it strips any field the
extractor was not authorized to set. A prompt-injection that convinces the
model to emit "confidence": 1000 for an attacker-chosen CVE still has to
survive corroboration (§7.3) downstream — but the gate stops malformed or
out-of-contract output cold, right here.

Design rule enforced by tests: a REJECTED candidate never silently
becomes an accepted one. Rejections go to a quarantine list the caller
must handle; they are never coerced into claims.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

__all__ = ["GateResult", "validate_candidate", "gate_candidates"]

_SUBJECT_TYPES = {"THREAT_ACTOR", "MALWARE", "CVE", "INFRASTRUCTURE", "CAMPAIGN", "TTP"}
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_TECH_RE = re.compile(r"^T\d{4}(\.\d{3})?$")  # ATT&CK technique id
# Fields the extractor is allowed to set. Anything else is dropped, not
# trusted — an injected "action_eligible": true cannot ride in this way.
_ALLOWED_FIELDS = {
    "subject_type", "subject_value", "assertion", "object_value",
    "extraction_confidence_millis", "attack_technique_ids",
}


@dataclass
class GateResult:
    accepted: List[Dict[str, Any]] = field(default_factory=list)
    rejected: List[Tuple[Dict[str, Any], str]] = field(default_factory=list)


def validate_candidate(cand: Any) -> Tuple[bool, str]:
    if not isinstance(cand, dict):
        return False, "not an object"
    # strip unauthorized fields BEFORE validation (defense in depth)
    unknown = set(cand) - _ALLOWED_FIELDS
    if unknown:
        return False, "unauthorized field(s): %s" % ",".join(sorted(unknown))

    st = cand.get("subject_type")
    if st not in _SUBJECT_TYPES:
        return False, "bad subject_type %r" % st

    sv = cand.get("subject_value")
    if not isinstance(sv, str) or not (1 <= len(sv) <= 512):
        return False, "bad subject_value"
    if st == "CVE" and not _CVE_RE.match(sv):
        return False, "CVE subject_value not a CVE id: %r" % sv

    if not isinstance(cand.get("assertion"), str) or not cand["assertion"]:
        return False, "missing assertion"

    ov = cand.get("object_value")
    if ov is not None and (not isinstance(ov, str) or len(ov) > 512):
        return False, "bad object_value"

    conf = cand.get("extraction_confidence_millis")
    if not isinstance(conf, int) or isinstance(conf, bool) or not (0 <= conf <= 1000):
        return False, "confidence not int in [0,1000]"

    techs = cand.get("attack_technique_ids", [])
    if not isinstance(techs, list) or len(techs) > 32:
        return False, "attack_technique_ids not a list (<=32)"
    for t in techs:
        if not isinstance(t, str) or not _TECH_RE.match(t):
            return False, "bad ATT&CK technique id %r" % t

    return True, ""


def gate_candidates(candidates: Any) -> GateResult:
    """Validate a batch. Non-list input, or a list with any structure the
    gate cannot parse, yields rejections — never exceptions to the caller."""
    result = GateResult()
    if not isinstance(candidates, list):
        result.rejected.append(({"_raw": repr(candidates)[:200]}, "not a list"))
        return result
    for cand in candidates:
        ok, reason = validate_candidate(cand)
        if ok:
            # keep only allowed fields, in a fresh dict (no reference to
            # attacker-controlled object identity/extra keys)
            result.accepted.append({k: cand[k] for k in _ALLOWED_FIELDS if k in cand})
        else:
            result.rejected.append((cand if isinstance(cand, dict) else {"_raw": repr(cand)[:200]}, reason))
    return result

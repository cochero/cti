"""Deterministic resolution primitives — pure, no I/O (Arch §4.2).

Normalization is the whole game for exact-match clustering: two spellings
that normalize identically are the same alias. Keep it conservative — over-
normalizing merges distinct entities, which is worse than missing a merge
(a missed merge is a duplicate; a wrong merge is corrupted intelligence).
"""

import re
from typing import Optional

__all__ = ["normalize", "canonicalize_cve", "is_high_confidence_auto_merge"]

_WS = re.compile(r"\s+")
_PUNCT = re.compile(r"[^\w\s-]")
_CVE = re.compile(r"^\s*(cve)[-\s]*(\d{4})[-\s]*(\d{4,})\s*$", re.IGNORECASE)


def normalize(value: str) -> str:
    """Lowercase, strip punctuation (except hyphen), collapse whitespace.

    'HIDDEN COBRA' and 'Hidden Cobra' -> 'hidden cobra'. Hyphen is kept
    because it is semantic in IDs (APT-28) and technique ids; but see
    normalization note — 'APT28' and 'APT-28' do NOT merge here (different
    normalized forms). Such known-equivalents belong in the alias table as
    curated data, not in over-aggressive normalization."""
    v = _PUNCT.sub("", value.strip().lower())
    return _WS.sub(" ", v).strip()


def canonicalize_cve(value: str) -> Optional[str]:
    """Return the canonical 'CVE-YYYY-NNNN' form, or None if not a CVE.

    Unlike free-text names, CVE ids have a single true canonical form, so
    normalization here is aggressive and safe."""
    m = _CVE.match(value)
    if not m:
        return None
    return "CVE-%s-%s" % (m.group(2), m.group(3))


def is_high_confidence_auto_merge(similarity_millis: int) -> bool:
    """Only near-exact matches auto-merge; everything else adjudicates.

    Deliberately strict: the cost asymmetry (corrupted intel vs. a
    duplicate) means we auto-merge only what is essentially certain."""
    return similarity_millis >= 980

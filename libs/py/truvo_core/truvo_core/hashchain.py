"""Append-only hash-chained ledger entries.

The core primitive behind `ledger-svc` (Architecture v2 SS4.2, SS3.1-T7):
every scoring/action event becomes a LedgerEntry whose hash covers its
content AND the previous entry's hash, so any tampering anywhere in
history invalidates every later entry.

Persistence (Postgres) and the external anchor land in Sprints S3-S4;
this module is the pure, dependency-free core that both the service and
the replay verifier share.
"""

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

from truvo_core.canonical import canonical_json

__all__ = [
    "GENESIS_HASH",
    "LedgerEntry",
    "append_entry",
    "verify_chain",
    "replay_hashes",
    "ChainError",
]

GENESIS_HASH = "0" * 64


class ChainError(ValueError):
    """Raised when a chain fails verification."""


@dataclass(frozen=True)
class LedgerEntry:
    """One immutable ledger record.

    ``ts_iso`` is an ISO-8601 UTC string supplied by the caller (the
    service layer stamps it); the core stays clock-free so replays are
    fully deterministic.
    """

    seq: int
    ts_iso: str
    tenant: str
    actor: str          # service or user that produced the event
    kind: str           # e.g. "score.emitted", "action.commanded"
    payload: Dict[str, Any] = field(default_factory=dict)
    prev_hash: str = GENESIS_HASH
    entry_hash: str = ""

    def content(self) -> Dict[str, Any]:
        """The hashed portion of the entry (everything except entry_hash)."""
        return {
            "seq": self.seq,
            "ts_iso": self.ts_iso,
            "tenant": self.tenant,
            "actor": self.actor,
            "kind": self.kind,
            "payload": self.payload,
            "prev_hash": self.prev_hash,
        }

    def compute_hash(self) -> str:
        return hashlib.sha256(canonical_json(self.content())).hexdigest()


def append_entry(
    prev: Optional[LedgerEntry],
    *,
    ts_iso: str,
    tenant: str,
    actor: str,
    kind: str,
    payload: Dict[str, Any],
) -> LedgerEntry:
    """Create the next entry in a chain (or the genesis entry if prev is None)."""
    seq = 0 if prev is None else prev.seq + 1
    prev_hash = GENESIS_HASH if prev is None else prev.entry_hash
    entry = LedgerEntry(
        seq=seq,
        ts_iso=ts_iso,
        tenant=tenant,
        actor=actor,
        kind=kind,
        payload=payload,
        prev_hash=prev_hash,
    )
    return LedgerEntry(**{**entry.__dict__, "entry_hash": entry.compute_hash()})


def verify_chain(entries: Iterable[LedgerEntry]) -> int:
    """Verify linkage and content hashes of an entire chain.

    Returns the number of verified entries. Raises ChainError on the first
    inconsistency -- a failed verification is a sev-1, never a warning
    (Architecture v2 SS9.4).
    """
    count = 0
    prev: Optional[LedgerEntry] = None
    for entry in entries:
        expected_seq = 0 if prev is None else prev.seq + 1
        if entry.seq != expected_seq:
            raise ChainError(
                "seq gap at %d: expected %d" % (entry.seq, expected_seq)
            )
        expected_prev = GENESIS_HASH if prev is None else prev.entry_hash
        if entry.prev_hash != expected_prev:
            raise ChainError("broken linkage at seq %d" % entry.seq)
        if entry.compute_hash() != entry.entry_hash:
            raise ChainError("content hash mismatch at seq %d" % entry.seq)
        prev = entry
        count += 1
    return count


def replay_hashes(entries: List[LedgerEntry]) -> List[str]:
    """Recompute every hash from raw content only (ignoring stored hashes).

    This is the bit-for-bit replay check: rebuilding the chain from
    content must reproduce the stored hashes exactly.
    """
    rebuilt: List[str] = []
    prev: Optional[LedgerEntry] = None
    for entry in entries:
        fresh = append_entry(
            prev,
            ts_iso=entry.ts_iso,
            tenant=entry.tenant,
            actor=entry.actor,
            kind=entry.kind,
            payload=entry.payload,
        )
        rebuilt.append(fresh.entry_hash)
        prev = fresh
    return rebuilt

"""TRUVO shared primitives.

- canonical: deterministic JSON serialization (the byte-level foundation of
  the replay property -- Architecture v2 SS2.4).
- hashchain: append-only hash-chained ledger entries (Architecture v2 SS4.2
  `ledger-svc` core).
"""

from truvo_core.canonical import canonical_json
from truvo_core.hashchain import GENESIS_HASH, LedgerEntry, append_entry, verify_chain

__all__ = [
    "canonical_json",
    "GENESIS_HASH",
    "LedgerEntry",
    "append_entry",
    "verify_chain",
]

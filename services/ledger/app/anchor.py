"""Ledger anchoring (ADR-0004).

An anchor is a signed snapshot of a tenant's chain head. Held outside the
platform (customer S3/WORM bucket, ticket, email), it makes even a
full-chain rewrite detectable: the rewritten chain cannot reproduce the
anchored head hash at the anchored seq.

Signing v0: HMAC-SHA256 with a service key (TRUVO_ANCHOR_KEY). S7 replaces
this with per-tenant keys in the customer HSM/vault — the record format
does not change.
"""

import hashlib
import hmac
import os
from dataclasses import asdict, dataclass
from typing import Optional

from truvo_core.canonical import canonical_json

__all__ = ["AnchorRecord", "make_anchor", "verify_anchor_signature", "AnchorMismatch"]


def _key() -> bytes:
    return os.environ.get("TRUVO_ANCHOR_KEY", "dev-anchor-key-not-for-prod").encode()


class AnchorMismatch(ValueError):
    """The chain does not extend the anchored head — sev-1."""


@dataclass(frozen=True)
class AnchorRecord:
    tenant: str
    as_of_iso: str
    last_seq: int
    head_hash: str
    signature: str = ""

    def signable(self) -> dict:
        d = asdict(self)
        d.pop("signature")
        return d


def _sign(record: AnchorRecord) -> str:
    return hmac.new(
        _key(), canonical_json(record.signable()), hashlib.sha256
    ).hexdigest()


def make_anchor(tenant: str, as_of_iso: str, last_seq: int, head_hash: str) -> AnchorRecord:
    unsigned = AnchorRecord(
        tenant=tenant, as_of_iso=as_of_iso, last_seq=last_seq, head_hash=head_hash
    )
    return AnchorRecord(**{**asdict(unsigned), "signature": _sign(unsigned)})


def verify_anchor_signature(record: AnchorRecord) -> bool:
    return hmac.compare_digest(record.signature, _sign(record))


def check_chain_extends(chain, record: AnchorRecord) -> None:
    """Raise AnchorMismatch unless chain[last_seq] carries the anchored hash."""
    if not verify_anchor_signature(record):
        raise AnchorMismatch("anchor signature invalid")
    matching: Optional[str] = None
    for entry in chain:
        if entry.seq == record.last_seq:
            matching = entry.entry_hash
            break
    if matching is None:
        raise AnchorMismatch(
            "anchored seq %d missing from chain (truncated?)" % record.last_seq
        )
    if matching != record.head_hash:
        raise AnchorMismatch(
            "chain hash at seq %d does not match anchor — history was rewritten"
            % record.last_seq
        )

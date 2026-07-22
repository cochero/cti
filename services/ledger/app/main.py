"""ledger-svc — append-only hash-chained audit ledger.

Sprint S0 walking skeleton: in-memory chains (one per tenant), the real
API surface, and the verify/replay endpoints wired to truvo_core.

S3-S4 (per DEVELOPMENT_PLAN.md): Postgres persistence, mTLS service
identity, external hash anchoring, OTel instrumentation.
"""

from datetime import datetime, timezone
from threading import Lock
from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from truvo_core.hashchain import (
    ChainError,
    LedgerEntry,
    append_entry,
    replay_hashes,
    verify_chain,
)

app = FastAPI(title="truvo-ledger", version="0.1.0")

# --- in-memory store (S0 only; replaced by Postgres in S3) -------------------
_chains: Dict[str, List[LedgerEntry]] = {}
_lock = Lock()


class AppendRequest(BaseModel):
    tenant: str = Field(min_length=1)
    actor: str = Field(min_length=1)
    kind: str = Field(min_length=1)
    payload: Dict[str, Any] = Field(default_factory=dict)


class EntryOut(BaseModel):
    seq: int
    ts_iso: str
    tenant: str
    actor: str
    kind: str
    payload: Dict[str, Any]
    prev_hash: str
    entry_hash: str


@app.get("/healthz")
def healthz() -> Dict[str, str]:
    return {"status": "ok", "service": "ledger"}


@app.post("/v1/entries", response_model=EntryOut, status_code=201)
def append(req: AppendRequest) -> LedgerEntry:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    with _lock:
        chain = _chains.setdefault(req.tenant, [])
        prev = chain[-1] if chain else None
        try:
            entry = append_entry(
                prev,
                ts_iso=ts,
                tenant=req.tenant,
                actor=req.actor,
                kind=req.kind,
                payload=req.payload,
            )
        except (TypeError, ValueError) as exc:  # canonicalization failures
            raise HTTPException(status_code=422, detail=str(exc))
        chain.append(entry)
    return entry


@app.get("/v1/{tenant}/entries", response_model=List[EntryOut])
def list_entries(tenant: str) -> List[LedgerEntry]:
    return _chains.get(tenant, [])


@app.get("/v1/{tenant}/verify")
def verify(tenant: str) -> Dict[str, Any]:
    chain = _chains.get(tenant, [])
    try:
        count = verify_chain(chain)
    except ChainError as exc:
        # A failed verification is a sev-1 (Architecture v2 SS9.4).
        raise HTTPException(status_code=500, detail="CHAIN INVALID: %s" % exc)
    replay_ok = replay_hashes(chain) == [e.entry_hash for e in chain]
    return {"tenant": tenant, "entries": count, "chain_valid": True, "replay_ok": replay_ok}

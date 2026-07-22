"""ledger-svc — append-only hash-chained audit ledger.

Storage: PostgresStore when TRUVO_LEDGER_DB_URL is set (production path:
RLS-fenced `ledger_entries`, per-tenant advisory-lock append), MemoryStore
otherwise (unit tests, dependency-free dev).

Still S7 work: mTLS/SPIFFE caller identity — until then the caller's
tenant claim is trusted (recorded in THREAT_MODEL.md).
"""

from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from app.store import store_from_env
from truvo_core.hashchain import ChainError, LedgerEntry, replay_hashes, verify_chain

app = FastAPI(title="truvo-ledger", version="0.2.0")
store = store_from_env()


def use_store(new_store) -> None:
    """Swap the storage backend (tests, future DI). Import-time env
    selection is convenience, not contract."""
    global store
    store = new_store


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
    return {"status": "ok", "service": "ledger", "store": type(store).__name__}


@app.post("/v1/entries", response_model=EntryOut, status_code=201)
def append(req: AppendRequest) -> LedgerEntry:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    try:
        return store.append(
            ts_iso=ts, tenant=req.tenant, actor=req.actor, kind=req.kind,
            payload=req.payload,
        )
    except (TypeError, ValueError) as exc:  # canonicalization failures
        raise HTTPException(status_code=422, detail=str(exc))


@app.get("/v1/{tenant}/entries", response_model=List[EntryOut])
def list_entries(tenant: str) -> List[LedgerEntry]:
    return store.list(tenant)


@app.get("/v1/{tenant}/verify")
def verify(tenant: str) -> Dict[str, Any]:
    chain = store.list(tenant)
    try:
        count = verify_chain(chain)
    except ChainError as exc:
        # A failed verification is a sev-1 (Architecture v2 SS9.4).
        raise HTTPException(status_code=500, detail="CHAIN INVALID: %s" % exc)
    replay_ok = replay_hashes(chain) == [e.entry_hash for e in chain]
    return {"tenant": tenant, "entries": count, "chain_valid": True, "replay_ok": replay_ok}

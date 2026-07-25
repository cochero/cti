"""ledger-svc — append-only hash-chained audit ledger.

Storage: PostgresStore when TRUVO_LEDGER_DB_URL is set (production path:
RLS-fenced `ledger_entries`, per-tenant advisory-lock append), MemoryStore
otherwise (unit tests, dependency-free dev).

Still S7 work: mTLS/SPIFFE caller identity — until then the caller's
tenant claim is trusted (recorded in THREAT_MODEL.md).
"""

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.anchor import AnchorMismatch, AnchorRecord, check_chain_extends, make_anchor
from app.store import store_from_env
from app.svcgate import require_service_identity
from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field
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
def append(
    req: AppendRequest, caller: str = Depends(require_service_identity)
) -> LedgerEntry:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    try:
        return store.append(
            ts_iso=ts, tenant=req.tenant, actor=req.actor, kind=req.kind,
            payload=req.payload,
        )
    except (TypeError, ValueError) as exc:  # canonicalization failures
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/v1/{tenant}/entries", response_model=List[EntryOut])
def list_entries(tenant: str) -> List[LedgerEntry]:
    return store.list(tenant)


@app.get("/v1/{tenant}/verify")
def verify(
    tenant: str,
    anchor_as_of: Optional[str] = None,
    anchor_seq: Optional[int] = None,
    anchor_hash: Optional[str] = None,
    anchor_sig: Optional[str] = None,
) -> Dict[str, Any]:
    """Verify chain integrity; optionally also against an externally held
    anchor (ADR-0004) — pass the anchor record's fields as query params."""
    chain = store.list(tenant)
    try:
        count = verify_chain(chain)
    except ChainError as exc:
        # A failed verification is a sev-1 (Architecture v2 SS9.4).
        raise HTTPException(status_code=500, detail="CHAIN INVALID: %s" % exc) from exc
    replay_ok = replay_hashes(chain) == [e.entry_hash for e in chain]
    result: Dict[str, Any] = {
        "tenant": tenant, "entries": count, "chain_valid": True,
        "replay_ok": replay_ok,
    }
    if anchor_hash is not None:
        if anchor_as_of is None or anchor_seq is None or anchor_sig is None:
            raise HTTPException(
                status_code=422, detail="anchor check needs all four anchor_* params"
            )
        record = AnchorRecord(
            tenant=tenant, as_of_iso=anchor_as_of, last_seq=anchor_seq,
            head_hash=anchor_hash, signature=anchor_sig,
        )
        try:
            check_chain_extends(chain, record)
        except AnchorMismatch as exc:
            # Rewritten history that passed chain_valid: the exact attack
            # anchoring exists to catch. sev-1.
            raise HTTPException(status_code=500, detail="ANCHOR MISMATCH: %s" % exc) from exc
        result["anchor_ok"] = True
    return result


class AnchorOut(BaseModel):
    tenant: str
    as_of_iso: str
    last_seq: int
    head_hash: str
    signature: str


def _deliver_s3(record: AnchorRecord) -> Optional[str]:
    """Deliver an anchor to customer-controlled S3-compatible storage
    (WORM in production). Configured via TRUVO_ANCHOR_S3_* env; no-op when
    unset. Returns the object name delivered, if any."""
    endpoint = os.environ.get("TRUVO_ANCHOR_S3_ENDPOINT")
    if not endpoint:
        return None
    from minio import Minio

    client = Minio(
        endpoint,
        access_key=os.environ["TRUVO_ANCHOR_S3_ACCESS_KEY"],
        secret_key=os.environ["TRUVO_ANCHOR_S3_SECRET_KEY"],
        secure=os.environ.get("TRUVO_ANCHOR_S3_SECURE", "0") == "1",
    )
    bucket = os.environ.get("TRUVO_ANCHOR_S3_BUCKET", "truvo-anchors")
    if not client.bucket_exists(bucket):
        client.make_bucket(bucket)
    body = json.dumps(record.__dict__, sort_keys=True).encode()
    name = "%s/%s.json" % (record.tenant, record.as_of_iso.replace(":", "-"))
    import io as _io

    client.put_object(bucket, name, _io.BytesIO(body), len(body),
                      content_type="application/json")
    return name


@app.post("/v1/{tenant}/anchor", response_model=AnchorOut, status_code=201)
def create_anchor(
    tenant: str, caller: str = Depends(require_service_identity)
) -> AnchorRecord:
    """Snapshot and sign the current chain head; persist and deliver."""
    chain = store.list(tenant)
    if not chain:
        raise HTTPException(status_code=409, detail="empty chain: nothing to anchor")
    head = chain[-1]
    as_of = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    record = make_anchor(tenant, as_of, head.seq, head.entry_hash)
    store.save_anchor(record)
    _deliver_s3(record)
    return record


@app.get("/v1/{tenant}/anchors", response_model=List[AnchorOut])
def list_anchors(tenant: str) -> List[AnchorRecord]:
    return store.list_anchors(tenant)

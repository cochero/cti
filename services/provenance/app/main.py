"""provenance-svc — source registry, claim ledger, corroboration (Arch SS7).

The gate between "observed" and "believed": claims arrive (API or the
intel.claims.v1 consumer), get recorded append-only against a registered
source, and facts are computed on read — belief score plus the SS7.3
action-eligibility floor, both deterministic.

Requires TRUVO_PROVENANCE_DB_URL (no in-memory mode: provenance without
persistence is meaningless).
"""

import os
from typing import Any, Dict, List, Optional

import psycopg2
import psycopg2.pool
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from app.logic import BELIEF_VERSION, action_eligible, belief_millis

app = FastAPI(title="truvo-provenance", version="0.1.0")

_pool: Optional[psycopg2.pool.ThreadedConnectionPool] = None


def pool() -> psycopg2.pool.ThreadedConnectionPool:
    global _pool
    if _pool is None:
        dsn = os.environ.get("TRUVO_PROVENANCE_DB_URL")
        if not dsn:
            raise RuntimeError("TRUVO_PROVENANCE_DB_URL is required")
        _pool = psycopg2.pool.ThreadedConnectionPool(1, 8, dsn)
    return _pool


class SourceIn(BaseModel):
    source_id: str = Field(pattern=r"^src-[a-z0-9][a-z0-9-]{1,62}$")
    name: str = Field(min_length=1)
    source_type: str
    grade: str = "F"
    url: Optional[str] = None


class ClaimIn(BaseModel):
    claim_id: str
    source_id: str
    provenance_id: str
    observed_at_iso: str
    raw_artifact_hash: str = Field(min_length=64, max_length=64)
    extraction_model_version: str
    extraction_confidence_millis: int = Field(ge=0, le=1000)
    subject_type: str
    subject_value: str
    assertion: str
    object_value: Optional[str] = None
    attack_technique_ids: List[str] = Field(default_factory=list)


def _exec(sql: str, params: tuple, fetch: bool = False):
    conn = pool().getconn()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall() if fetch else None
        conn.commit()
        return rows
    except Exception:
        conn.rollback()
        raise
    finally:
        pool().putconn(conn)


@app.get("/healthz")
def healthz() -> Dict[str, str]:
    return {"status": "ok", "service": "provenance"}


@app.post("/v1/sources", status_code=201)
def register_source(src: SourceIn) -> Dict[str, str]:
    try:
        _exec(
            "INSERT INTO sources (source_id, name, source_type, grade, url)"
            " VALUES (%s, %s, %s, %s, %s)"
            " ON CONFLICT (source_id) DO UPDATE SET"
            " name = EXCLUDED.name, source_type = EXCLUDED.source_type,"
            " grade = EXCLUDED.grade, url = EXCLUDED.url",
            (src.source_id, src.name, src.source_type, src.grade, src.url),
        )
    except psycopg2.errors.CheckViolation as exc:
        raise HTTPException(status_code=422, detail=str(exc).splitlines()[0]) from exc
    return {"source_id": src.source_id}


@app.get("/v1/sources")
def list_sources() -> List[Dict[str, Any]]:
    rows = _exec(
        "SELECT source_id, name, source_type, grade, active FROM sources"
        " ORDER BY source_id",
        (), fetch=True,
    )
    return [
        {"source_id": r[0], "name": r[1], "source_type": r[2], "grade": r[3],
         "active": r[4]}
        for r in rows
    ]


@app.post("/v1/claims", status_code=201)
def ingest_claim(claim: ClaimIn) -> Dict[str, str]:
    try:
        _exec(
            "INSERT INTO claims (claim_id, source_id, provenance_id,"
            " observed_at_iso, raw_artifact_hash, extraction_model_version,"
            " extraction_confidence_millis, subject_type, subject_value,"
            " assertion, object_value, attack_technique_ids)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
            " ON CONFLICT (claim_id) DO NOTHING",  # idempotent: at-least-once consumer
            (
                claim.claim_id, claim.source_id, claim.provenance_id,
                claim.observed_at_iso, claim.raw_artifact_hash,
                claim.extraction_model_version, claim.extraction_confidence_millis,
                claim.subject_type, claim.subject_value, claim.assertion,
                claim.object_value, claim.attack_technique_ids,
            ),
        )
    except psycopg2.errors.ForeignKeyViolation:
        raise HTTPException(
            status_code=422,
            detail="unknown source_id %r — claims from unregistered sources"
                   " are refused, not defaulted" % claim.source_id,
        ) from None
    except psycopg2.errors.CheckViolation as exc:
        raise HTTPException(status_code=422, detail=str(exc).splitlines()[0]) from exc
    return {"claim_id": claim.claim_id}


@app.get("/v1/facts/{subject_type}/{subject_value}")
def get_fact(subject_type: str, subject_value: str) -> Dict[str, Any]:
    """Corroboration view: belief + SS7.3 eligibility, computed on read."""
    rows = _exec(
        "SELECT s.source_id, s.source_type, s.grade,"
        " max(c.extraction_confidence_millis)"
        " FROM claims c JOIN sources s USING (source_id)"
        " WHERE c.subject_type = %s AND c.subject_value = %s AND s.active"
        " GROUP BY s.source_id, s.source_type, s.grade",
        (subject_type, subject_value), fetch=True,
    )
    if not rows:
        raise HTTPException(status_code=404, detail="no claims for subject")
    source_rows = [(r[1], r[2], r[3]) for r in rows]
    return {
        "subject_type": subject_type,
        "subject_value": subject_value,
        "independent_sources": len(rows),
        "sources": [r[0] for r in rows],
        "belief_millis": belief_millis(source_rows),
        "belief_version": BELIEF_VERSION,
        "action_eligible": action_eligible(source_rows),
    }

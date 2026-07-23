"""entity-resolution-svc — resolve subject values to canonical entities.

Every subject (actor/malware/CVE/…) resolves to exactly one canonical
entity. Unknown values auto-create a singleton canonical entity (an entity
always resolves to *something*, even if only itself) so the pipeline never
stalls on an unseen name; curated aliases and adjudicated merges collapse
singletons over time.

CVEs canonicalize by format (one true form); names resolve by normalized
exact-match against the alias table. Fuzzy/embedding clustering is a later
enhancement and routes to the adjudication queue — it never auto-merges.

Requires TRUVO_ENTITY_DB_URL (truvo_app role). Global infrastructure, no
tenant RLS.
"""

import os
from typing import Any, Dict, List, Optional

import psycopg2
import psycopg2.pool
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from app.logic import canonicalize_cve, normalize

app = FastAPI(title="truvo-entity-resolution", version="0.1.0")

_pool: Optional[psycopg2.pool.ThreadedConnectionPool] = None


def pool() -> psycopg2.pool.ThreadedConnectionPool:
    global _pool
    if _pool is None:
        dsn = os.environ.get("TRUVO_ENTITY_DB_URL")
        if not dsn:
            raise RuntimeError("TRUVO_ENTITY_DB_URL is required")
        _pool = psycopg2.pool.ThreadedConnectionPool(1, 8, dsn)
    return _pool


class ResolveRequest(BaseModel):
    entity_type: str = Field(pattern="^(THREAT_ACTOR|MALWARE|CVE|INFRASTRUCTURE|CAMPAIGN|TTP)$")
    value: str = Field(min_length=1, max_length=512)


class AliasRequest(BaseModel):
    entity_type: str
    canonical_value: str = Field(min_length=1)
    alias_value: str = Field(min_length=1)
    source: str = "adjudicated"


class MergeRequest(BaseModel):
    entity_type: str
    keep_value: str
    merge_value: str


def _display_and_norm(entity_type: str, value: str) -> tuple:
    if entity_type == "CVE":
        canon = canonicalize_cve(value)
        if canon is None:
            raise HTTPException(422, "not a valid CVE id: %r" % value)
        return canon, canon.lower()
    return value.strip(), normalize(value)


def _resolve(cur, entity_type: str, value: str) -> Dict[str, Any]:
    display, norm = _display_and_norm(entity_type, value)
    cur.execute(
        "SELECT canonical_id FROM entity_aliases"
        " WHERE entity_type = %s AND normalized_value = %s",
        (entity_type, norm),
    )
    row = cur.fetchone()
    if row:
        cid = row[0]
        created = False
    else:
        # auto-create a singleton canonical entity + its own alias
        cur.execute(
            "INSERT INTO entities (entity_type, canonical_name) VALUES (%s, %s)"
            " RETURNING canonical_id",
            (entity_type, display),
        )
        cid = cur.fetchone()[0]
        cur.execute(
            "INSERT INTO entity_aliases (entity_type, normalized_value,"
            " display_value, canonical_id, source) VALUES (%s, %s, %s, %s, 'auto')",
            (entity_type, norm, display, cid),
        )
        created = True
    cur.execute("SELECT canonical_name FROM entities WHERE canonical_id = %s", (cid,))
    canonical_name = cur.fetchone()[0]
    return {"canonical_id": str(cid), "canonical_name": canonical_name,
            "created": created}


def _tx(fn):
    conn = pool().getconn()
    try:
        with conn.cursor() as cur:
            result = fn(cur)
        conn.commit()
        return result
    except Exception:
        conn.rollback()
        raise
    finally:
        pool().putconn(conn)


@app.get("/healthz")
def healthz() -> Dict[str, str]:
    return {"status": "ok", "service": "entity-resolution"}


@app.post("/v1/resolve")
def resolve(req: ResolveRequest) -> Dict[str, Any]:
    return _tx(lambda cur: _resolve(cur, req.entity_type, req.value))


@app.post("/v1/aliases", status_code=201)
def add_alias(req: AliasRequest) -> Dict[str, Any]:
    """Attach alias_value to the canonical entity of canonical_value.
    Creates the canonical entity if it doesn't exist yet."""
    def op(cur):
        canonical = _resolve(cur, req.entity_type, req.canonical_value)
        _display, norm = _display_and_norm(req.entity_type, req.alias_value)
        display = (canonicalize_cve(req.alias_value) if req.entity_type == "CVE"
                   else req.alias_value.strip())
        cur.execute(
            "INSERT INTO entity_aliases (entity_type, normalized_value,"
            " display_value, canonical_id, source) VALUES (%s, %s, %s, %s, %s)"
            " ON CONFLICT (entity_type, normalized_value) DO UPDATE"
            " SET canonical_id = EXCLUDED.canonical_id, source = EXCLUDED.source",
            (req.entity_type, norm, display, canonical["canonical_id"], req.source),
        )
        return {"canonical_id": canonical["canonical_id"], "alias_added": display}
    return _tx(op)


@app.post("/v1/merge")
def merge(req: MergeRequest) -> Dict[str, Any]:
    """Merge merge_value's entity INTO keep_value's entity: repoint all its
    aliases, delete the emptied canonical. Adjudicated action (§4.2)."""
    def op(cur):
        keep = _resolve(cur, req.entity_type, req.keep_value)
        merge_e = _resolve(cur, req.entity_type, req.merge_value)
        if keep["canonical_id"] == merge_e["canonical_id"]:
            return {"canonical_id": keep["canonical_id"], "already_same": True}
        cur.execute(
            "UPDATE entity_aliases SET canonical_id = %s, source = 'adjudicated'"
            " WHERE canonical_id = %s",
            (keep["canonical_id"], merge_e["canonical_id"]),
        )
        cur.execute("DELETE FROM entities WHERE canonical_id = %s",
                    (merge_e["canonical_id"],))
        return {"canonical_id": keep["canonical_id"], "merged": merge_e["canonical_id"]}
    return _tx(op)


@app.get("/v1/entities/{canonical_id}/aliases")
def list_aliases(canonical_id: str) -> List[Dict[str, Any]]:
    def op(cur):
        cur.execute(
            "SELECT display_value, source, confidence_millis FROM entity_aliases"
            " WHERE canonical_id = %s ORDER BY display_value",
            (canonical_id,),
        )
        return [{"value": r[0], "source": r[1], "confidence_millis": r[2]}
                for r in cur.fetchall()]
    return _tx(op)

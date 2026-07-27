"""detection-factory — compile prioritized threats into tested, signed rules.

POST /v1/rules: generate a Sigma rule from indicators, lint it, DETONATE it
against the benign corpus (+ malicious samples), and persist it. A rule
that fails detonation is stored 'rejected' — visible for audit, never
deployable. A rule that passes is 'staged' and SIGNED. Promotion to
'active' is a separate, explicit step (T3: nothing auto-deploys).

Signing v0: HMAC-SHA256 over content_sha256 with a per-tenant vault key
(same pattern as anchor keys, S7); Ed25519 rule signing is a later swap.
Requires TRUVO_DETECTION_DB_URL. Vault optional (dev falls back to env).
"""

import hashlib
import hmac
import os
import secrets as _secrets
from typing import Any, Dict, List, Optional

import psycopg2
import psycopg2.pool
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from app.detonate import DEFAULT_FP_BUDGET_MILLIS, detonate
from app.sigma import generate_sigma

app = FastAPI(title="truvo-detection-factory", version="0.1.0")
GENERATOR_VERSION = "sigma-gen-v0.1"

_pool: Optional[psycopg2.pool.ThreadedConnectionPool] = None


def pool() -> psycopg2.pool.ThreadedConnectionPool:
    global _pool
    if _pool is None:
        dsn = os.environ.get("TRUVO_DETECTION_DB_URL")
        if not dsn:
            raise RuntimeError("TRUVO_DETECTION_DB_URL is required")
        _pool = psycopg2.pool.ThreadedConnectionPool(1, 8, dsn)
    return _pool


def _rule_key(tenant: str) -> bytes:
    if os.environ.get("TRUVO_VAULT_ADDR"):
        from truvo_secrets import SecretsClient
        client = SecretsClient()
        path = "truvo/tenants/%s" % tenant
        try:
            key = client.kv_get("secret", path)["rule_key"]
        except KeyError:
            key = _secrets.token_hex(32)
            # preserve any existing keys at this path (e.g. anchor_key)
            existing = {}
            try:
                existing = client.kv_get("secret", path)
            except KeyError:
                pass
            existing["rule_key"] = key
            client.kv_put("secret", path, existing)
        return key.encode()
    return os.environ.get("TRUVO_RULE_KEY", "dev-rule-key-not-for-prod").encode()


def _sign(tenant: str, content_sha: str) -> str:
    return hmac.new(_rule_key(tenant), content_sha.encode(), hashlib.sha256).hexdigest()


class RuleRequest(BaseModel):
    tenant: str = Field(min_length=1)
    cve: str = Field(min_length=1)
    title: str = Field(min_length=1)
    indicators: Dict[str, Any]
    malicious_samples: List[Dict[str, Any]] = Field(default_factory=list)
    fp_budget_millis: int = Field(default=DEFAULT_FP_BUDGET_MILLIS, ge=0, le=1000)


def _tenant_conn():
    return pool().getconn()


@app.get("/healthz")
def healthz() -> Dict[str, str]:
    return {"status": "ok", "service": "detection-factory",
            "generator": GENERATOR_VERSION}


@app.post("/v1/rules", status_code=201)
def create_rule(req: RuleRequest) -> Dict[str, Any]:
    try:
        content = generate_sigma(req.cve, req.title, req.indicators)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc

    result = detonate(content, req.malicious_samples, req.fp_budget_millis)
    content_sha = hashlib.sha256(content.encode()).hexdigest()
    status = "staged" if result.passed else "rejected"
    # only sign content that passed detonation — a rejected rule is never
    # given a valid signature, so it can never be mistaken for deployable
    signature = _sign(req.tenant, content_sha) if result.passed else ("0" * 64)

    conn = _tenant_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("BEGIN")
            cur.execute("SELECT set_config('truvo.tenant_id', %s, true)", (req.tenant,))
            cur.execute("SELECT 1 FROM tenants WHERE tenant_id = %s", (req.tenant,))
            if cur.fetchone() is None:
                conn.rollback()
                raise HTTPException(404, "unknown tenant")
            cur.execute(
                "INSERT INTO detection_rules (tenant_id, cve, title, content,"
                " content_sha256, signature, status, fp_estimate_millis,"
                " generator_version) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)"
                " RETURNING rule_id",
                (req.tenant, req.cve, req.title, content, content_sha, signature,
                 status, result.fp_millis, GENERATOR_VERSION),
            )
            rule_id = cur.fetchone()[0]
        conn.commit()
    except HTTPException:
        raise
    except Exception:
        conn.rollback()
        raise
    finally:
        pool().putconn(conn)

    return {
        "rule_id": str(rule_id), "cve": req.cve, "status": status,
        "content": content, "content_sha256": content_sha, "signature": signature,
        "detonation": {
            "passed": result.passed, "reason": result.reason,
            "fp_millis": result.fp_millis, "true_positives": result.true_positives,
            "lint_problems": result.lint_problems,
        },
    }


@app.post("/v1/rules/{rule_id}/promote")
def promote_rule(rule_id: str, tenant: str) -> Dict[str, Any]:
    """staged -> active. Refuses to promote a rejected rule or one whose
    signature doesn't verify (tamper check before deployment)."""
    conn = _tenant_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("BEGIN")
            cur.execute("SELECT set_config('truvo.tenant_id', %s, true)", (tenant,))
            cur.execute(
                "SELECT status, content_sha256, signature FROM detection_rules"
                " WHERE rule_id = %s", (rule_id,))
            row = cur.fetchone()
            if row is None:
                conn.rollback()
                raise HTTPException(404, "rule not found")
            status, content_sha, signature = row
            if status == "rejected":
                conn.rollback()
                raise HTTPException(409, "cannot promote a rejected rule")
            if not hmac.compare_digest(signature, _sign(tenant, content_sha)):
                conn.rollback()
                raise HTTPException(409, "signature invalid — rule tampered")
            cur.execute(
                "UPDATE detection_rules SET status = 'active', activated_at = now()"
                " WHERE rule_id = %s", (rule_id,))
        conn.commit()
    except HTTPException:
        raise
    except Exception:
        conn.rollback()
        raise
    finally:
        pool().putconn(conn)
    return {"rule_id": rule_id, "status": "active"}


@app.get("/v1/{tenant}/rules")
def list_rules(tenant: str, status: Optional[str] = None) -> Dict[str, Any]:
    conn = _tenant_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("BEGIN")
            cur.execute("SELECT set_config('truvo.tenant_id', %s, true)", (tenant,))
            if status:
                cur.execute(
                    "SELECT rule_id, cve, title, status, fp_estimate_millis"
                    " FROM detection_rules WHERE tenant_id=%s AND status=%s"
                    " ORDER BY created_at DESC", (tenant, status))
            else:
                cur.execute(
                    "SELECT rule_id, cve, title, status, fp_estimate_millis"
                    " FROM detection_rules WHERE tenant_id=%s"
                    " ORDER BY created_at DESC", (tenant,))
            rows = cur.fetchall()
        conn.commit()
    finally:
        pool().putconn(conn)
    return {"tenant": tenant, "count": len(rows),
            "rules": [{"rule_id": str(r[0]), "cve": r[1], "title": r[2],
                       "status": r[3], "fp_millis": r[4]} for r in rows]}

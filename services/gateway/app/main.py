"""gateway-svc — the outbound push to customer SIEM/EDR (Architecture v2 §8.3).

Receives SIGNED commands from response-orchestrator and pushes approved
actions to the customer's platform. Enforces §8.3 end to end:
- every command is Ed25519-signed (truvo_svcauth); unsigned/tampered/stale
  is refused, even from inside our network (assume T4/T8 breach);
- a single-use nonce per tenant defeats replay even within the sig window;
- SIEM credentials are resolved from the vault per push, never stored here
  (T4: stolen DB access must not yield customer SIEM tokens).

Requires TRUVO_GATEWAY_DB_URL. Signing is mandatory when TRUVO_SVCAUTH=1
(staging/prod default); the caller's pubkey comes from the vault.
"""

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import psycopg2
import psycopg2.pool
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field
from truvo_core.hashchain import LedgerEntry, append_entry
from truvo_svcauth import SvcAuthError, verify_headers

from app.adapters import adapter_for

app = FastAPI(title="truvo-gateway", version="0.1.0")

_pool: Optional[psycopg2.pool.ThreadedConnectionPool] = None
_pubkey_cache: Dict[str, str] = {}


def pool() -> psycopg2.pool.ThreadedConnectionPool:
    global _pool
    if _pool is None:
        dsn = os.environ.get("TRUVO_GATEWAY_DB_URL")
        if not dsn:
            raise RuntimeError("TRUVO_GATEWAY_DB_URL is required")
        _pool = psycopg2.pool.ThreadedConnectionPool(1, 8, dsn)
    return _pool


def _get_pubkey(svc: str) -> str:
    if svc in _pubkey_cache:
        return _pubkey_cache[svc]
    from truvo_secrets import SecretsClient
    key = SecretsClient().kv_get("secret", "truvo/services/%s" % svc)["pubkey"]
    _pubkey_cache[svc] = key
    return key


def _tenant_siem_creds(tenant: str, adapter: str) -> Dict[str, str]:
    """Resolve the customer SIEM credentials from the vault (never stored in
    our DB). Dev falls back to an env token so the fake adapter works."""
    if os.environ.get("TRUVO_VAULT_ADDR"):
        from truvo_secrets import SecretsClient
        try:
            return SecretsClient().kv_get(
                "secret", "truvo/tenants/%s/siem/%s" % (tenant, adapter))
        except KeyError:
            return {}
    return {"token": os.environ.get("TRUVO_DEV_SIEM_TOKEN", "dev-token")}


class PushCommand(BaseModel):
    tenant: str = Field(min_length=1)
    nonce: str = Field(min_length=8)
    action_type: str = Field(min_length=1)
    target: str = Field(min_length=1)
    adapter: str = Field(default="fake")


async def _verify(request: Request, body: bytes) -> str:
    if os.environ.get("TRUVO_SVCAUTH") != "1":
        return "anonymous"
    try:
        return verify_headers(dict(request.headers), request.method,
                              request.url.path, body, _get_pubkey)
    except (SvcAuthError, KeyError) as exc:
        raise HTTPException(401, "command auth: %s" % exc) from exc


def _ledger_append(cur, tenant: str, payload: Dict[str, Any]) -> int:
    cur.execute("SELECT pg_advisory_xact_lock(hashtext('ledger:' || %s))", (tenant,))
    cur.execute("SELECT seq, ts_iso, actor, kind, payload, prev_hash, entry_hash"
                " FROM ledger_entries WHERE tenant_id=%s ORDER BY seq DESC LIMIT 1",
                (tenant,))
    row = cur.fetchone()
    prev = LedgerEntry(seq=row[0], ts_iso=row[1], tenant=tenant, actor=row[2],
                       kind=row[3], payload=row[4], prev_hash=row[5],
                       entry_hash=row[6]) if row else None
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    entry = append_entry(prev, ts_iso=ts, tenant=tenant, actor="gateway-svc",
                         kind="command.pushed", payload=payload)
    cur.execute("INSERT INTO ledger_entries (tenant_id, seq, ts_iso, actor, kind,"
                " payload, prev_hash, entry_hash) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                (tenant, entry.seq, entry.ts_iso, entry.actor, entry.kind,
                 json.dumps(entry.payload), entry.prev_hash, entry.entry_hash))
    return entry.seq


@app.get("/healthz")
def healthz() -> Dict[str, str]:
    return {"status": "ok", "service": "gateway"}


@app.post("/v1/push", status_code=201)
async def push(request: Request) -> Dict[str, Any]:
    body = await request.body()
    await _verify(request, body)         # signature/expiry/tamper — refuse if bad
    try:
        cmd = PushCommand(**json.loads(body))
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise HTTPException(422, "bad command: %s" % exc) from exc

    adapter = adapter_for(cmd.adapter)
    if adapter is None:
        raise HTTPException(422, "unknown adapter %r" % cmd.adapter)

    conn = pool().getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("BEGIN")
            cur.execute("SELECT set_config('truvo.tenant_id', %s, true)", (cmd.tenant,))
            cur.execute("SELECT 1 FROM tenants WHERE tenant_id=%s", (cmd.tenant,))
            if cur.fetchone() is None:
                conn.rollback()
                raise HTTPException(404, "unknown tenant")
            # nonce single-use per tenant -> replay defense (unique violation)
            try:
                cur.execute(
                    "INSERT INTO gateway_commands (tenant_id, nonce, action_type,"
                    " target, adapter) VALUES (%s,%s,%s,%s,%s) RETURNING command_id",
                    (cmd.tenant, cmd.nonce, cmd.action_type, cmd.target, cmd.adapter))
            except psycopg2.errors.UniqueViolation:
                conn.rollback()
                raise HTTPException(409, "replayed nonce") from None
            command_id = cur.fetchone()[0]

            creds = _tenant_siem_creds(cmd.tenant, cmd.adapter)
            result = adapter.push(cmd.action_type, cmd.target, creds)
            seq = _ledger_append(cur, cmd.tenant, {
                "command_id": str(command_id), "action_type": cmd.action_type,
                "target": cmd.target, "adapter": cmd.adapter, "pushed": result.ok})
            cur.execute(
                "UPDATE gateway_commands SET pushed=%s, push_detail=%s, ledger_seq=%s"
                " WHERE command_id=%s",
                (result.ok, result.detail, seq, command_id))
        conn.commit()
    except HTTPException:
        raise
    except Exception:
        conn.rollback()
        raise
    finally:
        pool().putconn(conn)

    return {"command_id": str(command_id), "pushed": result.ok,
            "detail": result.detail, "ledger_seq": seq}


@app.get("/v1/{tenant}/commands")
def list_commands(tenant: str, limit: int = 50) -> Dict[str, Any]:
    conn = pool().getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("BEGIN")
            cur.execute("SELECT set_config('truvo.tenant_id', %s, true)", (tenant,))
            cur.execute("SELECT command_id, action_type, target, adapter, pushed"
                        " FROM gateway_commands WHERE tenant_id=%s"
                        " ORDER BY created_at DESC LIMIT %s", (tenant, limit))
            rows = cur.fetchall()
        conn.commit()
    finally:
        pool().putconn(conn)
    return {"tenant": tenant, "count": len(rows),
            "commands": [{"command_id": str(r[0]), "action_type": r[1],
                          "target": r[2], "adapter": r[3], "pushed": r[4]}
                         for r in rows]}

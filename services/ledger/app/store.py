"""Ledger storage backends.

PostgresStore is the production path: `ledger_entries` (db/migrations/0003)
with RLS enforced — the service connects as `truvo_app` and sets the tenant
context per transaction, so even a bug in this service cannot read or write
across tenants. MemoryStore remains for unit tests and dependency-free dev.

Append concurrency: a per-tenant advisory lock serializes appends inside
the transaction, so seq assignment is race-free without table locks.
"""

import os
from contextlib import contextmanager
from threading import Lock
from typing import Dict, List, Optional

from truvo_core.hashchain import LedgerEntry, append_entry


class MemoryStore:
    def __init__(self) -> None:
        self._chains: Dict[str, List[LedgerEntry]] = {}
        self._anchors: Dict[str, list] = {}
        self._lock = Lock()

    def save_anchor(self, record) -> None:
        with self._lock:
            self._anchors.setdefault(record.tenant, []).append(record)

    def list_anchors(self, tenant: str) -> list:
        return list(self._anchors.get(tenant, []))

    def append(self, *, ts_iso, tenant, actor, kind, payload) -> LedgerEntry:
        with self._lock:
            chain = self._chains.setdefault(tenant, [])
            prev = chain[-1] if chain else None
            entry = append_entry(
                prev, ts_iso=ts_iso, tenant=tenant, actor=actor, kind=kind,
                payload=payload,
            )
            chain.append(entry)
            return entry

    def list(self, tenant: str) -> List[LedgerEntry]:
        return list(self._chains.get(tenant, []))

    def clear(self) -> None:
        self._chains.clear()


class PostgresStore:
    def __init__(self, dsn: str) -> None:
        import psycopg2.pool

        self._pool = psycopg2.pool.ThreadedConnectionPool(1, 8, dsn)

    @contextmanager
    def _tenant_conn(self, tenant: str):
        conn = self._pool.getconn()
        try:
            with conn.cursor() as cur:
                # transaction-scoped (true): context cannot leak across
                # pooled connection reuse
                cur.execute("BEGIN")
                cur.execute(
                    "SELECT set_config('truvo.tenant_id', %s, true)", (tenant,)
                )
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self._pool.putconn(conn)

    def append(self, *, ts_iso, tenant, actor, kind, payload) -> LedgerEntry:
        import json

        with self._tenant_conn(tenant) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT pg_advisory_xact_lock(hashtext('ledger:' || %s))",
                    (tenant,),
                )
                cur.execute(
                    "SELECT seq, ts_iso, actor, kind, payload, prev_hash, entry_hash"
                    " FROM ledger_entries WHERE tenant_id = %s"
                    " ORDER BY seq DESC LIMIT 1",
                    (tenant,),
                )
                row = cur.fetchone()
                prev = (
                    LedgerEntry(
                        seq=row[0], ts_iso=row[1], tenant=tenant, actor=row[2],
                        kind=row[3], payload=row[4], prev_hash=row[5],
                        entry_hash=row[6],
                    )
                    if row
                    else None
                )
                entry = append_entry(
                    prev, ts_iso=ts_iso, tenant=tenant, actor=actor, kind=kind,
                    payload=payload,
                )
                cur.execute(
                    "INSERT INTO ledger_entries (tenant_id, seq, ts_iso, actor,"
                    " kind, payload, prev_hash, entry_hash)"
                    " VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                    (
                        tenant, entry.seq, entry.ts_iso, entry.actor, entry.kind,
                        json.dumps(entry.payload), entry.prev_hash, entry.entry_hash,
                    ),
                )
                return entry

    def list(self, tenant: str) -> List[LedgerEntry]:
        with self._tenant_conn(tenant) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT seq, ts_iso, actor, kind, payload, prev_hash, entry_hash"
                    " FROM ledger_entries WHERE tenant_id = %s ORDER BY seq",
                    (tenant,),
                )
                return [
                    LedgerEntry(
                        seq=r[0], ts_iso=r[1], tenant=tenant, actor=r[2], kind=r[3],
                        payload=r[4], prev_hash=r[5], entry_hash=r[6],
                    )
                    for r in cur.fetchall()
                ]

    def save_anchor(self, record) -> None:
        with self._tenant_conn(record.tenant) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO anchors (tenant_id, as_of_iso, last_seq,"
                    " head_hash, signature) VALUES (%s, %s, %s, %s, %s)",
                    (
                        record.tenant, record.as_of_iso, record.last_seq,
                        record.head_hash, record.signature,
                    ),
                )

    def list_anchors(self, tenant: str) -> list:
        from app.anchor import AnchorRecord

        with self._tenant_conn(tenant) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT as_of_iso, last_seq, head_hash, signature FROM anchors"
                    " WHERE tenant_id = %s ORDER BY as_of_iso",
                    (tenant,),
                )
                return [
                    AnchorRecord(
                        tenant=tenant, as_of_iso=r[0], last_seq=r[1],
                        head_hash=r[2], signature=r[3],
                    )
                    for r in cur.fetchall()
                ]


def store_from_env() -> object:
    dsn: Optional[str] = os.environ.get("TRUVO_LEDGER_DB_URL")
    if dsn:
        return PostgresStore(dsn)
    return MemoryStore()

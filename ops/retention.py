#!/usr/bin/env python3
"""Retention enforcement — the DPA's promises, executing (review H5).

The Data Governance policy accepted at onboarding promises:
  - raw collected artifacts retained 13 months (then GC'd)
  - leaked-credential records purged on a schedule (default 90 days)
This job enforces both on the schedule the cycle gives it, and writes a
ledger entry per affected tenant so a purge is itself auditable — the
compliance file proving the compliance file.

    python ops/retention.py      # env like run_cycle + TRUVO_APP_DB_URL
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

ARTIFACT_DAYS = int(os.environ.get("TRUVO_RETENTION_ARTIFACT_DAYS", "396"))
CRED_DAYS = int(os.environ.get("TRUVO_RETENTION_CREDENTIAL_DAYS", "90"))


def purge_credentials(cur) -> dict:
    """credential_leaks older than the schedule, per tenant, with a
    ledger entry recording exactly how many and when.

    The table is RLS-fenced (it holds the most sensitive rows we keep),
    so selection itself must run under each tenant's context — the job
    iterates tenants rather than aggregating globally, by design."""
    from truvo_core.hashchain import LedgerEntry, append_entry

    cur.execute("SELECT tenant_id FROM tenants WHERE status = 'active'")
    tenants = [str(r[0]) for r in cur.fetchall()]
    purged_tenants = total_rows = 0
    for tenant in tenants:
        cur.execute("BEGIN")
        try:
            cur.execute("SELECT set_config('truvo.tenant_id', %s, true)",
                        (tenant,))
            cur.execute(
                "SELECT count(*) FROM credential_leaks"
                " WHERE discovered_at < now() - (%s || ' days')::interval",
                (str(CRED_DAYS),))
            n_old = cur.fetchone()[0]
            if not n_old:
                cur.execute("COMMIT")
                continue
            cur.execute(
                "DELETE FROM credential_leaks WHERE discovered_at <"
                " now() - (%s || ' days')::interval", (str(CRED_DAYS),))
            deleted = cur.rowcount
            cur.execute(
                "SELECT seq, ts_iso, actor, kind, payload, prev_hash,"
                " entry_hash FROM ledger_entries WHERE tenant_id = %s"
                " ORDER BY seq DESC LIMIT 1", (tenant,))
            row = cur.fetchone()
            prev_entry = LedgerEntry(
                seq=row[0], ts_iso=row[1], tenant=tenant,
                actor=row[2], kind=row[3], payload=row[4],
                prev_hash=row[5], entry_hash=row[6]) if row else None
            entry = append_entry(
                prev_entry,
                ts_iso=datetime.now(timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%S.%fZ"),
                tenant=tenant, actor="retention-job",
                kind="retention.purged",
                payload={"what": "credential_leaks", "rows": deleted,
                         "older_than_days": CRED_DAYS})
            cur.execute(
                "INSERT INTO ledger_entries (tenant_id, seq, ts_iso, actor,"
                " kind, payload, prev_hash, entry_hash)"
                " VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                (tenant, entry.seq, entry.ts_iso, entry.actor,
                 entry.kind, json.dumps(entry.payload), entry.prev_hash,
                 entry.entry_hash))
            cur.execute("COMMIT")
            purged_tenants += 1
            total_rows += deleted
        except Exception:
            cur.execute("ROLLBACK")
            raise
    return {"tenants_purged": purged_tenants,
            "credential_rows": total_rows}


def gc_artifacts() -> dict:
    from truvo_objstore import ObjectStore

    store = ObjectStore(bucket=os.environ.get("TRUVO_RAW_BUCKET", "truvo-raw"))
    deleted = 0
    for key, _modified in store.iter_objects(older_than_days=ARTIFACT_DAYS):
        store.delete(key)
        deleted += 1
    return {"artifact_objects_deleted": deleted,
            "older_than_days": ARTIFACT_DAYS}


def main() -> int:
    import psycopg2

    summary = {"ran_at": datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")}
    dsn = os.environ.get("TRUVO_APP_DB_URL")
    if dsn:
        conn = psycopg2.connect(dsn)
        try:
            with conn.cursor() as cur:
                summary.update(purge_credentials(cur))
        finally:
            conn.close()
    if os.environ.get("TRUVO_OBJSTORE_ENDPOINT"):
        summary.update(gc_artifacts())
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())

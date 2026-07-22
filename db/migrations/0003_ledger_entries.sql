-- 0003: ledger_entries — first tenant-scoped table, and the reference
-- implementation of the RLS pattern (db/README.md).
--
-- Columns mirror truvo_core.hashchain.LedgerEntry. The service layer
-- (ledger-svc, S3) computes hashes over canonical JSON *before* insert;
-- payload jsonb here is storage, never the hashing source.
-- Append-only by construction: truvo_app gets SELECT + INSERT only.

CREATE TABLE IF NOT EXISTS ledger_entries (
    tenant_id  uuid      NOT NULL REFERENCES tenants (tenant_id),
    seq        bigint    NOT NULL CHECK (seq >= 0),
    ts_iso     text      NOT NULL,
    actor      text      NOT NULL,
    kind       text      NOT NULL,
    payload    jsonb     NOT NULL DEFAULT '{}'::jsonb,
    prev_hash  char(64)  NOT NULL,
    entry_hash char(64)  NOT NULL,
    PRIMARY KEY (tenant_id, seq)
);

ALTER TABLE ledger_entries ENABLE ROW LEVEL SECURITY;
-- FORCE: the policy applies even to the table owner (non-superuser).
ALTER TABLE ledger_entries FORCE ROW LEVEL SECURITY;

-- One policy, both directions: reads (USING) and writes (WITH CHECK)
-- are fenced to the connection's tenant context.
DROP POLICY IF EXISTS tenant_isolation ON ledger_entries;
CREATE POLICY tenant_isolation ON ledger_entries
    USING (tenant_id = truvo_current_tenant())
    WITH CHECK (tenant_id = truvo_current_tenant());

GRANT SELECT, INSERT ON ledger_entries TO truvo_app;
-- No UPDATE, no DELETE, for anyone but superuser maintenance: append-only.

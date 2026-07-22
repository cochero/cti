-- 0006: ledger anchors (ADR-0004).
-- Tenant-scoped, RLS-fenced, append-only: an anchor is a signed snapshot
-- of a chain head, delivered to customer-controlled storage. Rewriting
-- anchors defeats their purpose -> no UPDATE/DELETE for the app role.

CREATE TABLE IF NOT EXISTS anchors (
    tenant_id  uuid        NOT NULL REFERENCES tenants (tenant_id),
    as_of_iso  text        NOT NULL,
    last_seq   bigint      NOT NULL CHECK (last_seq >= 0),
    head_hash  char(64)    NOT NULL,
    signature  char(64)    NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, as_of_iso)
);

ALTER TABLE anchors ENABLE ROW LEVEL SECURITY;
ALTER TABLE anchors FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON anchors;
CREATE POLICY tenant_isolation ON anchors
    USING (tenant_id = truvo_current_tenant())
    WITH CHECK (tenant_id = truvo_current_tenant());

GRANT SELECT, INSERT ON anchors TO truvo_app;
REVOKE UPDATE, DELETE ON anchors FROM truvo_app;

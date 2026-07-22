-- 0007: identity snapshots (identity-telemetry-svc, Architecture v2 SS4.2).
-- Tenant-scoped mirror of the customer's IdP state (Entra ID / Okta):
-- the input to blast-radius computation. Mutable by design — each sync
-- replaces the tenant's snapshot — but always inside the RLS fence.

CREATE TABLE IF NOT EXISTS identities (
    tenant_id    uuid    NOT NULL REFERENCES tenants (tenant_id),
    source       text    NOT NULL CHECK (source IN ('entra', 'okta', 'fake')),
    principal_id text    NOT NULL,
    kind         text    NOT NULL CHECK (kind IN ('user', 'service', 'group')),
    display      text    NOT NULL DEFAULT '',
    privileged   boolean NOT NULL DEFAULT false,
    roles        text[]  NOT NULL DEFAULT '{}',
    synced_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, source, principal_id)
);

CREATE INDEX IF NOT EXISTS identities_privileged_idx
    ON identities (tenant_id, privileged) WHERE privileged;

ALTER TABLE identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE identities FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON identities;
CREATE POLICY tenant_isolation ON identities
    USING (tenant_id = truvo_current_tenant())
    WITH CHECK (tenant_id = truvo_current_tenant());

GRANT SELECT, INSERT, UPDATE, DELETE ON identities TO truvo_app;

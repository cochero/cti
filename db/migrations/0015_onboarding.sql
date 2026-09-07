-- 0015: tenant onboarding (Architecture v2 §11 legal + §12 deployment).
--
-- One onboarding record per tenant, created by a platform operator at the
-- start of the wizard and mutated step by step. Legal acceptances cite the
-- EXACT document versions accepted (enforced in code, recorded on the
-- tenant's hash-chained ledger — provable consent, not a checkbox claim).
--
-- NO RLS here, deliberately: this is platform-operational metadata, not
-- tenant data (same ADR-0003 reasoning as the tenants table itself — the
-- registry legitimately spans tenants). The tenant-scoped rows it creates
-- (assets, watch domains, ledger entries) are RLS-fenced and written under
-- the TARGET tenant's context explicitly, per-request.

CREATE TABLE IF NOT EXISTS onboarding_records (
    tenant_id     uuid PRIMARY KEY REFERENCES tenants (tenant_id),
    status        text NOT NULL DEFAULT 'in_progress'
                  CHECK (status IN ('in_progress', 'completed', 'abandoned')),
    current_step  text NOT NULL DEFAULT 'basics'
                  CHECK (current_step IN
                  ('basics', 'legal', 'admin', 'environment', 'review')),
    state         jsonb NOT NULL DEFAULT '{}',
                  -- company info, deployment profile, IdP config, notes
    legal         jsonb NOT NULL DEFAULT '{}',
                  -- {doc_id: {version, accepted_by, accepted_at_iso}}
    created_by    text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    completed_at  timestamptz
);

GRANT SELECT, INSERT, UPDATE ON onboarding_records TO truvo_app;
REVOKE DELETE ON onboarding_records FROM truvo_app;

CREATE INDEX IF NOT EXISTS onboarding_records_status_idx
    ON onboarding_records (status, created_at DESC);

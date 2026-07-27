-- 0011: detection engineering factory (Architecture v2 §4.2 Hunt, §9.3, §3.1-T3).
--
-- Compiled detection content (Sigma-first) per tenant. Tenant-scoped +
-- RLS: a detection rule reveals what a tenant is defending and how, so it
-- is as sensitive as the tenant's posture. Append-only: a rule version is
-- a historical artifact; supersession creates a new row, never mutates.
--
-- status lifecycle (T3 malicious-content guard): every rule starts in
-- 'staged' and only a reviewed/tested transition promotes it to 'active';
-- a rule that fails the FP-budget detonation test is 'rejected'.

CREATE TABLE IF NOT EXISTS detection_rules (
    rule_id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      uuid NOT NULL REFERENCES tenants (tenant_id),
    cve            text NOT NULL,
    format         text NOT NULL DEFAULT 'sigma'
                   CHECK (format IN ('sigma', 'yara', 'kql', 'spl')),
    title          text NOT NULL,
    content        text NOT NULL,          -- the rule source
    content_sha256 char(64) NOT NULL,      -- what was signed
    signature      char(64) NOT NULL,      -- Ed25519 / HMAC over content_sha256
    status         text NOT NULL DEFAULT 'staged'
                   CHECK (status IN ('staged', 'active', 'rejected', 'superseded')),
    fp_estimate_millis int NOT NULL DEFAULT 0
                   CHECK (fp_estimate_millis BETWEEN 0 AND 1000),
    generator_version text NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    activated_at   timestamptz
);

CREATE INDEX IF NOT EXISTS detection_rules_tenant_status_idx
    ON detection_rules (tenant_id, status);

ALTER TABLE detection_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection_rules FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON detection_rules;
CREATE POLICY tenant_isolation ON detection_rules
    USING (tenant_id = truvo_current_tenant())
    WITH CHECK (tenant_id = truvo_current_tenant());

-- staged->active/rejected is an UPDATE of status; content is never mutated
-- (enforced in the service). No DELETE for the app role.
GRANT SELECT, INSERT, UPDATE ON detection_rules TO truvo_app;
REVOKE DELETE ON detection_rules FROM truvo_app;

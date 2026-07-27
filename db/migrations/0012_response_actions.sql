-- 0012: response actions audit (Architecture v2 §8, §3.1-T8).
--
-- Every proposed outbound action and the orchestrator's verdict on it.
-- Tenant-scoped + RLS + append-only: the action log is the accountability
-- record (who/what/when/why an action was taken or withheld). The full
-- reasoning also goes to the hash-chained ledger; this table is the queue
-- index + the source of circuit-breaker state (recent action counts).

CREATE TABLE IF NOT EXISTS response_actions (
    action_id      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      uuid NOT NULL REFERENCES tenants (tenant_id),
    action_type    text NOT NULL,          -- e.g. isolate_host, block_hash
    target         text NOT NULL,          -- asset/identity acted on
    evidence_level int NOT NULL,           -- §7.3 ladder (1..4)
    criticality    int NOT NULL,           -- 1..3
    reversible     boolean NOT NULL,
    decided_tier   int NOT NULL,           -- 1..3
    executed       boolean NOT NULL DEFAULT false,  -- did it autonomously run?
    verdict        text NOT NULL,          -- approved | policy | human | blocked
    reason         text NOT NULL,
    ledger_seq     bigint,
    created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS response_actions_recent_idx
    ON response_actions (tenant_id, created_at);

ALTER TABLE response_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE response_actions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON response_actions;
CREATE POLICY tenant_isolation ON response_actions
    USING (tenant_id = truvo_current_tenant())
    WITH CHECK (tenant_id = truvo_current_tenant());
GRANT SELECT, INSERT ON response_actions TO truvo_app;
REVOKE UPDATE, DELETE ON response_actions FROM truvo_app;

-- The global-velocity breaker (§8.2) needs a CROSS-TENANT count — a
-- platform-wide action spike signals that TRUVO itself may be compromised.
-- That count must bypass RLS, so it lives in a SECURITY DEFINER function
-- owned by the (BYPASSRLS/superuser) migration role. It returns ONLY an
-- aggregate integer — never any tenant's rows — so it leaks nothing.
CREATE OR REPLACE FUNCTION truvo_global_action_count(since interval)
RETURNS bigint LANGUAGE sql SECURITY DEFINER STABLE AS $$
    SELECT count(*) FROM response_actions WHERE created_at > now() - since
$$;
REVOKE ALL ON FUNCTION truvo_global_action_count(interval) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION truvo_global_action_count(interval) TO truvo_app;

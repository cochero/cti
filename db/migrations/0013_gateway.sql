-- 0013: outbound command gateway (Architecture v2 §8.3, §3.1-T4/T8).
--
-- Every command the gateway receives (from response-orchestrator) and its
-- push result. Tenant-scoped + RLS + append-only: this is the record of
-- what TRUVO actually did to a customer environment. The nonce column is
-- the replay-defense ledger — a nonce may be used exactly once per tenant.
--
-- Credentials for the customer SIEM/EDR are NOT here — they live in the
-- vault, resolved per push (T4: stolen DB access must not yield customer
-- SIEM tokens).

CREATE TABLE IF NOT EXISTS gateway_commands (
    command_id   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    uuid NOT NULL REFERENCES tenants (tenant_id),
    nonce        text NOT NULL,
    action_type  text NOT NULL,
    target       text NOT NULL,
    adapter      text NOT NULL,           -- fake | splunk | sentinel | ...
    pushed       boolean NOT NULL DEFAULT false,
    push_detail  text NOT NULL DEFAULT '',
    ledger_seq   bigint,
    created_at   timestamptz NOT NULL DEFAULT now(),
    -- a nonce is single-use per tenant: this is the replay guard
    UNIQUE (tenant_id, nonce)
);

CREATE INDEX IF NOT EXISTS gateway_commands_tenant_idx
    ON gateway_commands (tenant_id, created_at);

ALTER TABLE gateway_commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE gateway_commands FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON gateway_commands;
CREATE POLICY tenant_isolation ON gateway_commands
    USING (tenant_id = truvo_current_tenant())
    WITH CHECK (tenant_id = truvo_current_tenant());
GRANT SELECT, INSERT, UPDATE ON gateway_commands TO truvo_app;
REVOKE DELETE ON gateway_commands FROM truvo_app;

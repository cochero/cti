-- 0010: scoring engine tables (Architecture v2 §6.4, §9.3).
--
-- tenant_assets  : the client's tech stack (CPE inventory) + sector.
--                  Tenant-scoped, RLS-fenced — this is a customer's
--                  vulnerability surface, the most sensitive data we hold.
-- exploit_intel  : EPSS / KEV / PoC maturity per CVE. Global infra.
-- scores         : emitted priority scores over time. Tenant-scoped, RLS,
--                  append-only (a score is a historical fact; the ledger
--                  holds its full decomposition, this table is the index).
-- ground_truth   : did a scored threat materialize? The dataset competitors
--                  can't buy (§5.3, §9.2). Tenant-scoped, RLS.

-- --- tenant tech stack (RLS) -------------------------------------------------
CREATE TABLE IF NOT EXISTS tenant_assets (
    tenant_id  uuid NOT NULL REFERENCES tenants (tenant_id),
    cpe        text NOT NULL,   -- e.g. cpe:2.3:a:apache:log4j:2.14.1
    vendor     text NOT NULL DEFAULT '',
    product    text NOT NULL DEFAULT '',
    count      int  NOT NULL DEFAULT 1 CHECK (count >= 0),
    added_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, cpe)
);
ALTER TABLE tenant_assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_assets FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON tenant_assets;
CREATE POLICY tenant_isolation ON tenant_assets
    USING (tenant_id = truvo_current_tenant())
    WITH CHECK (tenant_id = truvo_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_assets TO truvo_app;

CREATE TABLE IF NOT EXISTS tenant_sector (
    tenant_id uuid PRIMARY KEY REFERENCES tenants (tenant_id),
    sector    text NOT NULL
);
ALTER TABLE tenant_sector ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_sector FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON tenant_sector;
CREATE POLICY tenant_isolation ON tenant_sector
    USING (tenant_id = truvo_current_tenant())
    WITH CHECK (tenant_id = truvo_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_sector TO truvo_app;

-- --- global exploit intel ----------------------------------------------------
CREATE TABLE IF NOT EXISTS exploit_intel (
    cve             text PRIMARY KEY,
    epss_millis     int NOT NULL DEFAULT 0 CHECK (epss_millis BETWEEN 0 AND 1000),
    kev             boolean NOT NULL DEFAULT false,   -- CISA Known Exploited
    poc_public      boolean NOT NULL DEFAULT false,
    cvss_millis     int NOT NULL DEFAULT 0 CHECK (cvss_millis BETWEEN 0 AND 1000),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE ON exploit_intel TO truvo_app;

-- --- emitted scores (RLS, append-only) ---------------------------------------
CREATE TABLE IF NOT EXISTS scores (
    tenant_id       uuid NOT NULL REFERENCES tenants (tenant_id),
    cve             text NOT NULL,
    scored_at       timestamptz NOT NULL DEFAULT now(),
    priority_millis int NOT NULL CHECK (priority_millis BETWEEN 0 AND 1000),
    weights_version text NOT NULL,
    ledger_seq      bigint,   -- link to the ledger entry holding the decomposition
    PRIMARY KEY (tenant_id, cve, scored_at)
);
ALTER TABLE scores ENABLE ROW LEVEL SECURITY;
ALTER TABLE scores FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON scores;
CREATE POLICY tenant_isolation ON scores
    USING (tenant_id = truvo_current_tenant())
    WITH CHECK (tenant_id = truvo_current_tenant());
GRANT SELECT, INSERT ON scores TO truvo_app;
REVOKE UPDATE, DELETE ON scores FROM truvo_app;

-- --- ground truth (RLS) — the calibration/backtest dataset -------------------
CREATE TABLE IF NOT EXISTS ground_truth (
    tenant_id     uuid NOT NULL REFERENCES tenants (tenant_id),
    cve           text NOT NULL,
    as_of         timestamptz NOT NULL DEFAULT now(),
    materialized  boolean NOT NULL,   -- did relevant activity actually occur?
    detail        text NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, cve, as_of)
);
ALTER TABLE ground_truth ENABLE ROW LEVEL SECURITY;
ALTER TABLE ground_truth FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON ground_truth;
CREATE POLICY tenant_isolation ON ground_truth
    USING (tenant_id = truvo_current_tenant())
    WITH CHECK (tenant_id = truvo_current_tenant());
GRANT SELECT, INSERT ON ground_truth TO truvo_app;

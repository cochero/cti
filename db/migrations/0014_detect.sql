-- 0014: continuous monitoring — detect-svc (Architecture v2 §4.2 Detect, §11.3).
--
-- tenant_watchlist : IOCs the tenant monitors (their IPs/domains/hashes).
--                    Inbound intel IOCs are cross-referenced against this.
-- tenant_domains   : the customer's registered domains — the ONLY scope for
--                    credential-leak monitoring (§11.3: we search for THEIR
--                    assets, we do not warehouse the internet's stolen PII).
-- credential_leaks : discovered leaks. Stores a SALTED HASH of the
--                    credential + metadata; cleartext is NEVER persisted.
-- All tenant-scoped + RLS.

CREATE TABLE IF NOT EXISTS tenant_watchlist (
    tenant_id  uuid NOT NULL REFERENCES tenants (tenant_id),
    ioc_type   text NOT NULL CHECK (ioc_type IN ('ip', 'domain', 'sha256', 'md5', 'url')),
    ioc_value  text NOT NULL,
    added_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, ioc_type, ioc_value)
);
ALTER TABLE tenant_watchlist ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_watchlist FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON tenant_watchlist;
CREATE POLICY tenant_isolation ON tenant_watchlist
    USING (tenant_id = truvo_current_tenant())
    WITH CHECK (tenant_id = truvo_current_tenant());
GRANT SELECT, INSERT, DELETE ON tenant_watchlist TO truvo_app;

CREATE TABLE IF NOT EXISTS tenant_domains (
    tenant_id uuid NOT NULL REFERENCES tenants (tenant_id),
    domain    text NOT NULL,
    PRIMARY KEY (tenant_id, domain)
);
ALTER TABLE tenant_domains ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_domains FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON tenant_domains;
CREATE POLICY tenant_isolation ON tenant_domains
    USING (tenant_id = truvo_current_tenant())
    WITH CHECK (tenant_id = truvo_current_tenant());
GRANT SELECT, INSERT, DELETE ON tenant_domains TO truvo_app;

CREATE TABLE IF NOT EXISTS credential_leaks (
    tenant_id     uuid NOT NULL REFERENCES tenants (tenant_id),
    local_part    text NOT NULL,          -- user part of the email (their asset)
    domain        text NOT NULL,          -- always a registered tenant domain
    cred_salted_sha256 char(64) NOT NULL, -- salted hash; NEVER the cleartext
    source        text NOT NULL,          -- breach name/id
    discovered_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, domain, local_part, source)
);
ALTER TABLE credential_leaks ENABLE ROW LEVEL SECURITY;
ALTER TABLE credential_leaks FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON credential_leaks;
CREATE POLICY tenant_isolation ON credential_leaks
    USING (tenant_id = truvo_current_tenant())
    WITH CHECK (tenant_id = truvo_current_tenant());
GRANT SELECT, INSERT ON credential_leaks TO truvo_app;
REVOKE UPDATE, DELETE ON credential_leaks FROM truvo_app;

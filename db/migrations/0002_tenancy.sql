-- 0002: tenants table + tenant-context helper.
-- Tenant provisioning is an admin/deploy operation: truvo_app can read
-- the tenant registry but never write it.

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    slug       text UNIQUE NOT NULL CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
    name       text NOT NULL,
    status     text NOT NULL DEFAULT 'active'
               CHECK (status IN ('active', 'suspended', 'offboarding')),
    created_at timestamptz NOT NULL DEFAULT now()
);

-- The single source of tenant context. Services set it per connection or
-- per transaction:  SELECT set_config('truvo.tenant_id', '<uuid>', true);
-- Returns NULL when unset -> every RLS policy comparison fails -> zero rows.
CREATE OR REPLACE FUNCTION truvo_current_tenant() RETURNS uuid
LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT NULLIF(current_setting('truvo.tenant_id', true), '')::uuid
$$;

GRANT SELECT ON tenants TO truvo_app;

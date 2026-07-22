-- 0001: application role.
-- truvo_app is the identity every service connects as in dev/staging.
-- It is deliberately weak: no SUPERUSER, no BYPASSRLS, no CREATEROLE —
-- RLS policies therefore always apply to it. The leak-test suite asserts
-- these attributes so privilege drift fails CI.
--
-- Passwords: dev-only value here; staging/prod rotate via vault
-- (ALTER ROLE ... PASSWORD) during deploy — never in a migration.

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'truvo_app') THEN
        CREATE ROLE truvo_app LOGIN PASSWORD 'truvo-app-dev-only'
            NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
    END IF;
END
$$;

GRANT CONNECT ON DATABASE truvo TO truvo_app;
GRANT USAGE ON SCHEMA public TO truvo_app;

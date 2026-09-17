-- 0017: retention purge path (security review H5).
--
-- credential_leaks is append-only for the app role BY DESIGN — nobody
-- quietly edits leak records. But the DPA promises scheduled purges, and
-- a purge nobody can execute is a promise nobody can audit.
--
-- Mechanics: GRANT DELETE, then a RESTRICTIVE policy limiting deletable
-- rows to aged ones only. Restrictive policies AND-combine with the
-- permissive tenant_isolation policy, so the app role can delete exactly:
-- same-tenant AND older-than-schedule. Everything else stays append-only.

DROP POLICY IF EXISTS retention_purge_only ON credential_leaks;

CREATE POLICY retention_purge_only ON credential_leaks
    AS RESTRICTIVE FOR DELETE
    USING (discovered_at < now() - interval '90 days');

GRANT DELETE ON credential_leaks TO truvo_app;

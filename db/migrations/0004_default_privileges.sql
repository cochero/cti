-- 0004: default privileges for Django-owned tables.
-- Django's migrations run as the admin role and create its tables (auth,
-- sessions, accounts_*). The runtime role truvo_app needs DML on those --
-- but never DDL, and never a blanket grant on tenant-scoped tables (those
-- keep their explicit per-table grants + RLS from 0003).
--
-- ALTER DEFAULT PRIVILEGES applies to tables created *by the admin role
-- (truvo)* after this migration runs, which is exactly the Django set.

ALTER DEFAULT PRIVILEGES FOR ROLE truvo IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO truvo_app;

ALTER DEFAULT PRIVILEGES FOR ROLE truvo IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO truvo_app;

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session")
def django_db_setup(django_db_setup, django_db_blocker):
    """After pytest-django creates the test DB, apply the SQL-first
    migrations so managed=False tables (tenants, ledger_entries) exist."""
    from django.conf import settings

    db = settings.DATABASES["default"]
    dsn = "postgresql://%s:%s@%s:%s/%s" % (
        db["USER"], db["PASSWORD"], db["HOST"], db["PORT"], db["NAME"]
    )
    sys.path.insert(0, str(REPO_ROOT / "db"))
    from migrate import migrate as run_sql_migrations

    with django_db_blocker.unblock():
        run_sql_migrations(dsn)


@pytest.fixture(autouse=True)
def _clear_throttle_cache():
    """DRF throttles key into the (shared, in-process) cache; without this,
    later auth tests inherit earlier tests' request counts and fail on
    429s that have nothing to do with the code under test."""
    from django.core.cache import cache
    cache.clear()
    yield
    cache.clear()

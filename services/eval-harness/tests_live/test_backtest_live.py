"""Backtest live: scores + ground truth -> calibration report, RLS-fenced.

Seeds a known score/outcome distribution and asserts the report's Brier,
precision@k, and reliability reflect it — and that RLS keeps one tenant's
backtest from seeing another's.

Env: TRUVO_TEST_DATABASE_URL. Run: pytest tests_live
"""

import os
import uuid

import pytest

ADMIN_URL = os.environ.get("TRUVO_TEST_DATABASE_URL")
APP_URL = "postgresql://truvo_app:truvo-app-dev-only@localhost:5432/truvo"

pytestmark = pytest.mark.skipif(
    not ADMIN_URL, reason="TRUVO_TEST_DATABASE_URL not set"
)

if ADMIN_URL:
    os.environ["TRUVO_EVAL_DB_URL"] = APP_URL
    import psycopg2

    from app.backtest import backtest


@pytest.fixture()
def scored_tenant():
    admin = psycopg2.connect(ADMIN_URL)
    admin.autocommit = True
    tid = str(uuid.uuid4())
    tag = uuid.uuid4().hex[:8]
    # a well-calibrated-ish set: high scores mostly materialize, low don't
    rows = [
        ("CVE-A-%s" % tag, 900, True), ("CVE-B-%s" % tag, 850, True),
        ("CVE-C-%s" % tag, 820, False), ("CVE-D-%s" % tag, 200, False),
        ("CVE-E-%s" % tag, 150, False), ("CVE-F-%s" % tag, 100, True),
    ]
    with admin.cursor() as cur:
        cur.execute("INSERT INTO tenants (tenant_id, slug, name) VALUES (%s,%s,'e')",
                    (tid, "ev-%s" % tag))
        for cve, pri, materialized in rows:
            cur.execute("INSERT INTO scores (tenant_id, cve, priority_millis,"
                        " weights_version) VALUES (%s,%s,%s,'weights-v0')",
                        (tid, cve, pri))
            cur.execute("INSERT INTO ground_truth (tenant_id, cve, materialized)"
                        " VALUES (%s,%s,%s)", (tid, cve, materialized))
    yield tid, rows
    with admin.cursor() as cur:
        cur.execute("DELETE FROM scores WHERE tenant_id=%s", (tid,))
        cur.execute("DELETE FROM ground_truth WHERE tenant_id=%s", (tid,))
        cur.execute("DELETE FROM tenants WHERE tenant_id=%s", (tid,))
    admin.close()


def test_backtest_reports_sample_and_brier(scored_tenant):
    tid, rows = scored_tenant
    r = backtest(tid, top_k=3)
    assert r["sample"] == len(rows)
    assert r["brier"]["brier_e6"] is not None
    # this set is decent but not perfect -> brier strictly between 0 and 1
    assert 0 < r["brier"]["brier"] < 1


def test_precision_at_3_top_scores(scored_tenant):
    tid, _ = scored_tenant
    r = backtest(tid, top_k=3)
    # top 3 by score: 900(T), 850(T), 820(F) -> 2 of 3
    assert r["precision_at_k"]["k"] == 3
    assert r["precision_at_k"]["hits"] == 2
    assert r["precision_at_k"]["precision_millis"] == 666


def test_reliability_bands_present(scored_tenant):
    tid, _ = scored_tenant
    r = backtest(tid)
    assert len(r["reliability"]) >= 2  # high band + low band at least
    for band in r["reliability"]:
        assert 0 <= band["actual_rate_millis"] <= 1000


def test_rls_isolates_backtest(scored_tenant):
    tid, _ = scored_tenant
    other = str(uuid.uuid4())
    admin = psycopg2.connect(ADMIN_URL)
    admin.autocommit = True
    with admin.cursor() as cur:
        cur.execute("INSERT INTO tenants (tenant_id, slug, name) VALUES (%s,%s,'o')",
                    (other, "ev-o-%s" % other[:8]))
    try:
        r = backtest(other)
        assert r["sample"] == 0  # sees none of scored_tenant's data
    finally:
        with admin.cursor() as cur:
            cur.execute("DELETE FROM tenants WHERE tenant_id=%s", (other,))
        admin.close()

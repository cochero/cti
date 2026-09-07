"""enrich live: claims -> exploit_intel projection on real Postgres.

Seeds claims exactly as provenance-svc records them (structured-feed
assertions), runs the projection, and asserts the read model reflects the
LATEST claim per CVE, upserts preserve other columns, and re-running is
idempotent. This is the path that makes scoring run on real feed data.

Env: TRUVO_TEST_DATABASE_URL. Run: pytest tests_live
"""

import os
import uuid

import pytest

ADMIN_URL = os.environ.get("TRUVO_TEST_DATABASE_URL")
APP_URL = os.environ.get(
    "TRUVO_APP_DB_URL",
    "postgresql://truvo_app:truvo-app-dev-only@localhost:5432/truvo",
)

pytestmark = pytest.mark.skipif(
    not ADMIN_URL, reason="TRUVO_TEST_DATABASE_URL not set"
)

if ADMIN_URL:
    import psycopg2
    from app.enrich import run


def _cve(tag: str, n: int) -> str:
    return "CVE-2026-%04d" % ((int(tag[:4], 16) + n) % 10000)


@pytest.fixture()
def world():
    admin = psycopg2.connect(ADMIN_URL)
    admin.autocommit = True
    tag = uuid.uuid4().hex
    cve1, cve2 = _cve(tag, 0), _cve(tag, 1)
    src = "src-test-%s" % tag[:6]
    with admin.cursor() as cur:
        cur.execute(
            "INSERT INTO sources (source_id, name, source_type, grade)"
            " VALUES (%s, 't', 'cert', 'A')", (src,))
    claims = [
        # cve1: kev + epss (twice — later claim wins) + cvss
        _claim(admin, src, tag, cve1, "structured:kev_listed", "2026-01-10"),
        _claim(admin, src, tag, cve1, "structured:epss_score", "0.5"),
        _claim(admin, src, tag, cve1, "structured:epss_score", "0.97052"),
        _claim(admin, src, tag, cve1, "structured:cvss_score", "9.8"),
        # cve2: epss only
        _claim(admin, src, tag, cve2, "structured:epss_score", "0.00041"),
    ]
    yield {"cve1": cve1, "cve2": cve2}
    with admin.cursor() as cur:
        # truvo_app cannot UPDATE/DELETE claims (append-only) — admin can
        cur.execute("DELETE FROM claims WHERE claim_id = ANY(%s::uuid[])",
                    ([str(c) for c in claims],))
        cur.execute("DELETE FROM sources WHERE source_id = %s", (src,))
        cur.execute("DELETE FROM exploit_intel WHERE cve IN (%s, %s)",
                    (cve1, cve2))
    admin.close()


def _claim(admin, src, tag, cve, assertion, object_value):
    # id derives from (tag, assertion, value): the same source asserting a
    # NEW epss value is a new claim, not a duplicate
    cid = uuid.uuid5(uuid.NAMESPACE_URL,
                     "claim:%s:%s:%s" % (tag, assertion, object_value))
    with admin.cursor() as cur:
        cur.execute(
            "INSERT INTO claims (claim_id, source_id, provenance_id,"
            " observed_at_iso, raw_artifact_hash, extraction_model_version,"
            " extraction_confidence_millis, subject_type, subject_value,"
            " assertion, object_value)"
            " VALUES (%s, %s, %s, now(), %s, 'structured-feed-v0.1', 1000,"
            " 'CVE', %s, %s, %s)",
            (str(cid), src, str(uuid.uuid4()), "0" * 64, cve, assertion,
             object_value))
    return cid


def test_projection_latest_wins_and_upserts_preserve(world):
    admin = psycopg2.connect(ADMIN_URL)
    conn = psycopg2.connect(APP_URL)
    try:
        with conn.cursor() as cur:
            counts = run(cur)
        conn.commit()
        assert counts["kev"] >= 1 and counts["epss"] >= 2

        with conn.cursor() as cur:
            cur.execute(
                "SELECT epss_millis, kev, cvss_millis FROM exploit_intel"
                " WHERE cve = %s", (world["cve1"],))
            epss, kev, cvss = cur.fetchone()
            assert epss == 971          # 0.97052 -> millis, latest claim wins
            assert kev is True
            assert cvss == 980          # 9.8 -> millis

            cur.execute(
                "SELECT epss_millis, kev FROM exploit_intel WHERE cve = %s",
                (world["cve2"],))
            epss2, kev2 = cur.fetchone()
            assert epss2 == 0
            assert kev2 is False        # absent column stays default

        # idempotent: re-run changes nothing
        with conn.cursor() as cur:
            run(cur)
        conn.commit()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT epss_millis, kev, cvss_millis FROM exploit_intel"
                " WHERE cve = %s", (world["cve1"],))
            assert cur.fetchone() == (971, True, 980)
    finally:
        conn.close()
        admin.close()

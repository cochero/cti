"""Entity resolution live: seed, resolve aliases to one canonical, merge.

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
    os.environ["TRUVO_ENTITY_DB_URL"] = APP_URL
    import psycopg2
    from app.main import app
    from app.seed import seed
    from fastapi.testclient import TestClient

    client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def seeded():
    seed(ADMIN_URL)  # idempotent; loads curated aliases as admin


@pytest.fixture()
def cleanup_extra():
    """Track ad-hoc entities created by a test for teardown."""
    names = []
    yield names
    admin = psycopg2.connect(ADMIN_URL)
    admin.autocommit = True
    with admin.cursor() as cur:
        for et, val in names:
            cur.execute(
                "DELETE FROM entities WHERE canonical_id IN"
                " (SELECT canonical_id FROM entity_aliases"
                "  WHERE entity_type = %s AND normalized_value = lower(%s))",
                (et, val),
            )
    admin.close()


def test_lazarus_aliases_resolve_to_one_entity():
    ids = set()
    for name in ["Lazarus Group", "HIDDEN COBRA", "APT38", "Diamond Sleet",
                 "hidden cobra", "  ZINC  "]:
        r = client.post("/v1/resolve",
                        json={"entity_type": "THREAT_ACTOR", "value": name})
        assert r.status_code == 200, r.text
        ids.add(r.json()["canonical_id"])
        assert r.json()["canonical_name"] == "Lazarus Group"
    assert len(ids) == 1, "aliases resolved to %d entities, expected 1" % len(ids)


def test_apt28_separate_from_apt29():
    a = client.post("/v1/resolve",
                    json={"entity_type": "THREAT_ACTOR", "value": "Fancy Bear"}).json()
    b = client.post("/v1/resolve",
                    json={"entity_type": "THREAT_ACTOR", "value": "Cozy Bear"}).json()
    assert a["canonical_name"] == "APT28"
    assert b["canonical_name"] == "APT29"
    assert a["canonical_id"] != b["canonical_id"]


def test_cve_canonicalizes_across_spellings():
    forms = ["cve-2021-44228", "CVE-2021-44228", "CVE 2021 44228"]
    ids = {client.post("/v1/resolve",
                       json={"entity_type": "CVE", "value": f}).json()["canonical_id"]
           for f in forms}
    assert len(ids) == 1


def test_unknown_actor_creates_singleton(cleanup_extra):
    novel = "NovelActor-%s" % uuid.uuid4().hex[:8]
    cleanup_extra.append(("THREAT_ACTOR", novel))
    r = client.post("/v1/resolve",
                    json={"entity_type": "THREAT_ACTOR", "value": novel}).json()
    assert r["created"] is True
    # resolves stably to the same entity on repeat
    r2 = client.post("/v1/resolve",
                     json={"entity_type": "THREAT_ACTOR", "value": novel}).json()
    assert r2["created"] is False
    assert r2["canonical_id"] == r["canonical_id"]


def test_adjudicated_merge_collapses_singletons(cleanup_extra):
    a = "MysteryA-%s" % uuid.uuid4().hex[:8]
    b = "MysteryB-%s" % uuid.uuid4().hex[:8]
    cleanup_extra.append(("THREAT_ACTOR", a))
    id_a = client.post("/v1/resolve",
                       json={"entity_type": "THREAT_ACTOR", "value": a}).json()["canonical_id"]
    id_b = client.post("/v1/resolve",
                       json={"entity_type": "THREAT_ACTOR", "value": b}).json()["canonical_id"]
    assert id_a != id_b

    m = client.post("/v1/merge", json={
        "entity_type": "THREAT_ACTOR", "keep_value": a, "merge_value": b,
    })
    assert m.status_code == 200, m.text
    assert m.json()["canonical_id"] == id_a

    # b now resolves to a's canonical entity
    after = client.post("/v1/resolve",
                        json={"entity_type": "THREAT_ACTOR", "value": b}).json()
    assert after["canonical_id"] == id_a


def test_invalid_cve_rejected():
    r = client.post("/v1/resolve", json={"entity_type": "CVE", "value": "Lazarus"})
    assert r.status_code == 422

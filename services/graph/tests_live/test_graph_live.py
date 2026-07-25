"""Threat graph live: edge upsert, neighbors, attack-path traversal.

Builds a small known graph and asserts the recursive attack-path query
finds the right actors by the right routes — including cycle safety and
depth bounding.

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
    os.environ["TRUVO_GRAPH_DB_URL"] = APP_URL
    import psycopg2
    from app.main import app
    from fastapi.testclient import TestClient

    client = TestClient(app)


@pytest.fixture()
def graph():
    """A tagged subgraph, torn down after. All ids suffixed with a run tag
    so concurrent/re-runs never collide in the shared global table."""
    tag = uuid.uuid4().hex[:8]
    a = lambda n: "%s-%s" % (n, tag)  # noqa: E731
    edges = [
        # Lazarus uses malware AppleJeus, which exploits CVE-X
        ("THREAT_ACTOR", a("Lazarus"), "uses", "MALWARE", a("AppleJeus")),
        ("MALWARE", a("AppleJeus"), "exploits", "CVE", a("CVE-2026-1")),
        # APT28 uses Drovorub, also exploits CVE-X (two actors reach it)
        ("THREAT_ACTOR", a("APT28"), "uses", "MALWARE", a("Drovorub")),
        ("MALWARE", a("Drovorub"), "exploits", "CVE", a("CVE-2026-1")),
        # a deeper chain: APT29 -> campaign -> malware -> CVE-Y
        ("THREAT_ACTOR", a("APT29"), "attributed_to", "CAMPAIGN", a("SolarStorm")),
        ("CAMPAIGN", a("SolarStorm"), "uses", "MALWARE", a("Sunburst")),
        ("MALWARE", a("Sunburst"), "exploits", "CVE", a("CVE-2026-2")),
        # a cycle guard: malware variant_of each other
        ("MALWARE", a("AppleJeus"), "variant_of", "MALWARE", a("Drovorub")),
        ("MALWARE", a("Drovorub"), "variant_of", "MALWARE", a("AppleJeus")),
    ]
    for st, si, rel, dt, di in edges:
        r = client.post("/v1/edges", json={
            "src_type": st, "src_id": si, "rel": rel,
            "dst_type": dt, "dst_id": di,
        })
        assert r.status_code == 201, r.text
    yield a
    admin = psycopg2.connect(ADMIN_URL)
    admin.autocommit = True
    with admin.cursor() as cur:
        cur.execute("DELETE FROM graph_edges WHERE src_id LIKE %s OR dst_id LIKE %s",
                    ("%%-" + tag, "%%-" + tag))
    admin.close()


def test_neighbors_outbound(graph):
    a = graph
    r = client.get("/v1/neighbors/THREAT_ACTOR/%s" % a("Lazarus")).json()
    rels = {(n["rel"], n["node_id"]) for n in r["neighbors"]}
    assert ("uses", a("AppleJeus")) in rels


def test_attack_paths_finds_both_actors(graph):
    a = graph
    r = client.get("/v1/attack-paths/%s" % a("CVE-2026-1")).json()
    actors = {x["actor"] for x in r["actors"]}
    assert actors == {a("Lazarus"), a("APT28")}, actors


def test_attack_path_route_is_correct(graph):
    a = graph
    r = client.get("/v1/attack-paths/%s" % a("CVE-2026-1")).json()
    lazarus = next(x for x in r["actors"] if x["actor"] == a("Lazarus"))
    # path runs actor -> malware -> CVE (reversed from the walk)
    assert lazarus["path"][0] == "THREAT_ACTOR:%s" % a("Lazarus")
    assert lazarus["path"][-1] == "CVE:%s" % a("CVE-2026-1")


def test_deeper_chain_via_campaign(graph):
    a = graph
    r = client.get("/v1/attack-paths/%s" % a("CVE-2026-2")).json()
    assert {x["actor"] for x in r["actors"]} == {a("APT29")}
    path = r["actors"][0]["path"]
    assert "CAMPAIGN:%s" % a("SolarStorm") in path


def test_cycle_does_not_hang_or_duplicate(graph):
    a = graph
    # AppleJeus <-> Drovorub variant_of cycle exists; query must terminate
    r = client.get("/v1/attack-paths/%s?max_depth=8" % a("CVE-2026-1")).json()
    # each actor appears once despite the cycle
    assert len(r["actors"]) == r["actor_count"] == 2


def test_depth_bound_enforced(graph):
    a = graph
    # depth 1 from the CVE reaches only malware, no actors
    r = client.get("/v1/attack-paths/%s?max_depth=1" % a("CVE-2026-1")).json()
    assert r["actor_count"] == 0


def test_bad_depth_rejected():
    assert client.get("/v1/attack-paths/whatever?max_depth=99").status_code == 422

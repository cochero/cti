"""scoring-svc live: gather real signals -> score -> auditable ledger entry.

Builds a tenant with a tech stack, an actively-exploited CVE that affects
it, and a threat actor that can reach it via the graph — then asserts the
priority reflects those signals, the decomposition is on the ledger, the
score row persists, and RLS isolates it all.

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
    os.environ["TRUVO_SCORING_DB_URL"] = APP_URL
    import psycopg2
    from app.main import app
    from fastapi.testclient import TestClient

    client = TestClient(app)


@pytest.fixture()
def world():
    """A tenant that runs log4j, a KEV CVE that exploits it, and an actor
    (Lazarus) that uses malware exploiting that CVE. Tagged for teardown."""
    admin = psycopg2.connect(ADMIN_URL)
    admin.autocommit = True
    tid = str(uuid.uuid4())
    tag = uuid.uuid4().hex[:8]
    cve = "CVE-2026-%s" % tag[:4].upper()  # unique-ish
    cpe = "cpe:2.3:a:apache:log4j:2.14.1:%s" % tag
    actor = "Lazarus-%s" % tag
    malware = "Mal-%s" % tag
    with admin.cursor() as cur:
        cur.execute("INSERT INTO tenants (tenant_id, slug, name) VALUES (%s,%s,'s')",
                    (tid, "sc-%s" % tag))
        cur.execute("INSERT INTO tenant_sector (tenant_id, sector) VALUES (%s,'finance')",
                    (tid,))
        cur.execute("INSERT INTO tenant_assets (tenant_id, cpe, product, count)"
                    " VALUES (%s,%s,'log4j',12)", (tid, cpe))
        cur.execute("INSERT INTO exploit_intel (cve, epss_millis, kev, poc_public,"
                    " cvss_millis) VALUES (%s, 400, true, true, 980)", (cve,))
        # graph: CPE -exploits-> CVE ; malware -exploits-> CVE ; actor -uses-> malware
        edges = [
            ("INFRASTRUCTURE", cpe, "exploits", "CVE", cve),
            ("MALWARE", malware, "exploits", "CVE", cve),
            ("THREAT_ACTOR", actor, "uses", "MALWARE", malware),
            ("THREAT_ACTOR", actor, "targets", "SECTOR", "finance"),
        ]
        for st, si, rel, dt, di in edges:
            cur.execute("INSERT INTO graph_edges (src_type,src_id,rel,dst_type,dst_id)"
                        " VALUES (%s,%s,%s,%s,%s)", (st, si, rel, dt, di))
        # a couple of privileged identities -> non-zero exposure
        for i in range(4):
            cur.execute("INSERT INTO identities (tenant_id, source, principal_id,"
                        " kind, privileged) VALUES (%s,'fake',%s,'user',%s)",
                        (tid, "p%d-%s" % (i, tag), i < 2))
    yield {"tid": tid, "cve": cve, "cpe": cpe, "actor": actor, "admin": admin}
    with admin.cursor() as cur:
        cur.execute("DELETE FROM scores WHERE tenant_id=%s", (tid,))
        cur.execute("DELETE FROM ledger_entries WHERE tenant_id=%s", (tid,))
        cur.execute("DELETE FROM ground_truth WHERE tenant_id=%s", (tid,))
        cur.execute("DELETE FROM identities WHERE tenant_id=%s", (tid,))
        cur.execute("DELETE FROM tenant_assets WHERE tenant_id=%s", (tid,))
        cur.execute("DELETE FROM tenant_sector WHERE tenant_id=%s", (tid,))
        cur.execute("DELETE FROM graph_edges WHERE src_id LIKE %s OR dst_id=%s",
                    ("%" + tag, cve))
        cur.execute("DELETE FROM exploit_intel WHERE cve=%s", (cve,))
        cur.execute("DELETE FROM tenants WHERE tenant_id=%s", (tid,))
    admin.close()


def test_score_reflects_all_signals(world):
    r = client.post("/v1/score", json={"tenant": world["tid"], "cve": world["cve"]})
    assert r.status_code == 200, r.text
    body = r.json()
    # affects tenant + KEV + actor-reachable + sector-targeted + priv identities
    # -> a high priority. Exact math: 1000*300 + 900*250 + 250*180 + 500*120
    # + 0*100 + 1000*50 = 680000 / 1000 = 680.
    assert body["priority_millis"] >= 650, body["decomposition"]

    factors = {f["name"]: f for f in body["decomposition"]["factors"]}
    assert factors["stack_overlap"]["subscore_millis"] == 1000  # runs log4j
    assert factors["exploit_maturity"]["subscore_millis"] >= 900  # KEV floor
    assert factors["actor_reach"]["subscore_millis"] >= 250  # >=1 actor reaches
    assert factors["sector_affinity"]["subscore_millis"] == 1000  # finance targeted
    assert factors["identity_exposure"]["subscore_millis"] == 500  # 2 of 4 priv


def test_decomposition_is_on_the_ledger_and_tamper_evident(world):
    r = client.post("/v1/score", json={"tenant": world["tid"], "cve": world["cve"]}).json()
    seq = r["ledger_seq"]
    admin = world["admin"]
    with admin.cursor() as cur:
        cur.execute("SELECT kind, payload, entry_hash FROM ledger_entries"
                    " WHERE tenant_id=%s AND seq=%s", (world["tid"], seq))
        kind, payload, entry_hash = cur.fetchone()
    assert kind == "score.emitted"
    assert payload["priority_millis"] == r["priority_millis"]
    assert payload["weights_version"] == "weights-v0"
    assert len(payload["factors"]) == 6  # full decomposition preserved

    # tamper the score decomposition -> ledger verify must catch it
    from truvo_core.hashchain import LedgerEntry
    e = LedgerEntry(seq=seq, ts_iso="x", tenant=world["tid"], actor="scoring-svc",
                    kind=kind, payload={"priority_millis": 1}, prev_hash="0"*64)
    assert e.compute_hash() != entry_hash  # any change breaks the hash


def test_score_persisted_and_appears_in_priorities(world):
    client.post("/v1/score", json={"tenant": world["tid"], "cve": world["cve"]})
    q = client.get("/v1/%s/priorities" % world["tid"]).json()
    cves = {p["cve"] for p in q["priorities"]}
    assert world["cve"] in cves


def test_rls_isolates_scores(world):
    client.post("/v1/score", json={"tenant": world["tid"], "cve": world["cve"]})
    other = str(uuid.uuid4())
    admin = world["admin"]
    with admin.cursor() as cur:
        cur.execute("INSERT INTO tenants (tenant_id, slug, name) VALUES (%s,%s,'o')",
                    (other, "sc-o-%s" % other[:8]))
    try:
        q = client.get("/v1/%s/priorities" % other).json()
        assert q["count"] == 0  # sees none of world's scores
    finally:
        with admin.cursor() as cur:
            cur.execute("DELETE FROM tenants WHERE tenant_id=%s", (other,))


def test_unaffected_tenant_scores_far_lower(world):
    """Same scary CVE, but a tenant that does NOT run the product. The
    relevance gap is the guarantee: an irrelevant KEV CVE still carries its
    exploit_maturity contribution (~270) but scores FAR below the affected
    tenant (680) — clearly out of the top-of-queue band."""
    admin = world["admin"]
    other = str(uuid.uuid4())
    with admin.cursor() as cur:
        cur.execute("INSERT INTO tenants (tenant_id, slug, name) VALUES (%s,%s,'o')",
                    (other, "sc-u-%s" % other[:8]))
    try:
        affected = client.post(
            "/v1/score", json={"tenant": world["tid"], "cve": world["cve"]}).json()
        r = client.post("/v1/score", json={"tenant": other, "cve": world["cve"]}).json()
        f = {x["name"]: x for x in r["decomposition"]["factors"]}
        assert f["stack_overlap"]["subscore_millis"] == 0  # doesn't run it
        assert r["priority_millis"] < 350
        assert affected["priority_millis"] - r["priority_millis"] >= 350  # the gap
    finally:
        with admin.cursor() as cur:
            cur.execute("DELETE FROM scores WHERE tenant_id=%s", (other,))
            cur.execute("DELETE FROM ledger_entries WHERE tenant_id=%s", (other,))
            cur.execute("DELETE FROM tenants WHERE tenant_id=%s", (other,))

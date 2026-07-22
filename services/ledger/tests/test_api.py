from fastapi.testclient import TestClient

from app.main import app, store

client = TestClient(app)


def setup_function(_):
    store.clear()  # unit tier always runs on MemoryStore


def test_healthz():
    assert client.get("/healthz").json()["status"] == "ok"


def test_append_verify_roundtrip():
    for i in range(3):
        r = client.post(
            "/v1/entries",
            json={
                "tenant": "t1",
                "actor": "scoring-svc",
                "kind": "score.emitted",
                "payload": {"threat": "TA-%d" % i, "score_millis": 80000 + i},
            },
        )
        assert r.status_code == 201, r.text
        assert r.json()["seq"] == i

    v = client.get("/v1/t1/verify").json()
    assert v["chain_valid"] is True
    assert v["replay_ok"] is True
    assert v["entries"] == 3


def test_float_payload_rejected():
    r = client.post(
        "/v1/entries",
        json={
            "tenant": "t1",
            "actor": "scoring-svc",
            "kind": "score.emitted",
            "payload": {"score": 87.4},  # floats forbidden by canonical JSON
        },
    )
    assert r.status_code == 422


def test_tenants_are_isolated():
    client.post(
        "/v1/entries",
        json={"tenant": "t1", "actor": "a", "kind": "k", "payload": {}},
    )
    assert client.get("/v1/t2/entries").json() == []

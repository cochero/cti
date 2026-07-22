"""provenance-svc live: API + claim ledger + corroboration + backbone consumer.

Env: TRUVO_TEST_DATABASE_URL (admin; service itself runs as truvo_app).
Consumer test additionally needs TRUVO_KAFKA_BOOTSTRAP + TRUVO_SCHEMA_REGISTRY.
Run with: pytest tests_live
"""

import json
import os
import uuid
from pathlib import Path

import pytest

ADMIN_URL = os.environ.get("TRUVO_TEST_DATABASE_URL")
APP_URL = "postgresql://truvo_app:truvo-app-dev-only@localhost:5432/truvo"
KAFKA = os.environ.get("TRUVO_KAFKA_BOOTSTRAP")
REGISTRY = os.environ.get("TRUVO_SCHEMA_REGISTRY")

pytestmark = pytest.mark.skipif(
    not ADMIN_URL, reason="TRUVO_TEST_DATABASE_URL not set"
)

if ADMIN_URL:
    os.environ["TRUVO_PROVENANCE_DB_URL"] = APP_URL
    import psycopg2
    from fastapi.testclient import TestClient

    from app.main import app

    client = TestClient(app)


def make_claim(source_id, subject_value, conf=900):
    return {
        "claim_id": str(uuid.uuid4()),
        "source_id": source_id,
        "provenance_id": str(uuid.uuid4()),
        "observed_at_iso": "2026-07-22T00:00:00Z",
        "raw_artifact_hash": "b" * 64,
        "extraction_model_version": "ner-v0.1.0",
        "extraction_confidence_millis": conf,
        "subject_type": "CVE",
        "subject_value": subject_value,
        "assertion": "observed",
        "object_value": None,
        "attack_technique_ids": ["T1190"],
    }


@pytest.fixture()
def cleanup():
    created = {"sources": [], "subjects": []}
    yield created
    admin = psycopg2.connect(ADMIN_URL)
    admin.autocommit = True
    with admin.cursor() as cur:
        if created["subjects"]:
            cur.execute(
                "DELETE FROM claims WHERE subject_value = ANY(%s)",
                (created["subjects"],),
            )
        if created["sources"]:
            cur.execute(
                "DELETE FROM sources WHERE source_id = ANY(%s)",
                (created["sources"],),
            )
    admin.close()


def register(source_id, source_type, grade, cleanup):
    r = client.post(
        "/v1/sources",
        json={
            "source_id": source_id, "name": source_id,
            "source_type": source_type, "grade": grade,
        },
    )
    assert r.status_code == 201, r.text
    cleanup["sources"].append(source_id)


def test_claim_from_unregistered_source_refused(cleanup):
    subject = "CVE-2026-%s" % uuid.uuid4().hex[:6]
    cleanup["subjects"].append(subject)
    r = client.post("/v1/claims", json=make_claim("src-ghost", subject))
    assert r.status_code == 422
    assert "unregistered" in r.json()["detail"]


def test_corroboration_floor_end_to_end(cleanup):
    """The SS7.3 floor on live data: OSINT chatter never flips eligibility;
    a graded vendor advisory plus corroboration does."""
    subject = "CVE-2026-%s" % uuid.uuid4().hex[:6]
    cleanup["subjects"].append(subject)
    uniq = uuid.uuid4().hex[:6]
    osint1, osint2 = "src-osint-a-%s" % uniq, "src-osint-b-%s" % uniq
    vendor = "src-vendor-%s" % uniq
    register(osint1, "osint", "C", cleanup)
    register(osint2, "dark_web", "B", cleanup)
    register(vendor, "vendor_advisory", "A", cleanup)

    # one OSINT source -> not eligible
    assert client.post("/v1/claims", json=make_claim(osint1, subject)).status_code == 201
    fact = client.get("/v1/facts/CVE/%s" % subject).json()
    assert fact["independent_sources"] == 1
    assert fact["action_eligible"] is False

    # two independent OSINT sources -> corroborated but STILL not eligible
    assert client.post("/v1/claims", json=make_claim(osint2, subject)).status_code == 201
    fact = client.get("/v1/facts/CVE/%s" % subject).json()
    assert fact["independent_sources"] == 2
    assert fact["action_eligible"] is False, "OSINT alone crossed the floor: sev-1"

    # vendor advisory (grade A) joins -> eligible
    assert client.post("/v1/claims", json=make_claim(vendor, subject)).status_code == 201
    fact = client.get("/v1/facts/CVE/%s" % subject).json()
    assert fact["independent_sources"] == 3
    assert fact["action_eligible"] is True
    assert 0 < fact["belief_millis"] <= 1000


def test_ingest_is_idempotent(cleanup):
    subject = "CVE-2026-%s" % uuid.uuid4().hex[:6]
    cleanup["subjects"].append(subject)
    src = "src-idem-%s" % uuid.uuid4().hex[:6]
    register(src, "osint", "C", cleanup)
    claim = make_claim(src, subject)
    assert client.post("/v1/claims", json=claim).status_code == 201
    assert client.post("/v1/claims", json=claim).status_code == 201  # redelivery
    fact = client.get("/v1/facts/CVE/%s" % subject).json()
    assert fact["independent_sources"] == 1


@pytest.mark.skipif(
    not (KAFKA and REGISTRY), reason="Kafka env not set"
)
def test_backbone_consumer_end_to_end(cleanup):
    """Produce an intel.claims.v1 event -> consume_batch -> fact queryable."""
    from confluent_kafka import Producer

    from app.consumer import consume_batch
    from truvo_events import SchemaRegistry, encode

    subject = "CVE-2026-%s" % uuid.uuid4().hex[:6]
    cleanup["subjects"].append(subject)
    src = "src-stream-%s" % uuid.uuid4().hex[:6]
    register(src, "cert", "B", cleanup)

    contract = (
        Path(__file__).resolve().parents[3]
        / "contracts" / "events" / "intel.claim.v1.avsc"
    )
    schema = json.loads(contract.read_text(encoding="utf-8"))
    registry = SchemaRegistry(REGISTRY)
    schema_id = registry.register("intel.claims.v1-value", schema)

    event = dict(make_claim(src, subject), tenant="global", schema_version="1")
    producer = Producer({"bootstrap.servers": KAFKA})
    producer.produce("intel.claims.v1", value=encode(schema, schema_id, event))
    assert producer.flush(10) == 0

    ingested = consume_batch(
        max_messages=500, timeout_s=15.0, group="test-%s" % uuid.uuid4().hex[:8]
    )
    assert ingested >= 1

    fact = client.get("/v1/facts/CVE/%s" % subject).json()
    assert fact["independent_sources"] == 1
    assert src in fact["sources"]

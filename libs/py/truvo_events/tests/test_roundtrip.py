"""Event backbone round-trip (S1-S2 exit criterion).

Live test: register contracts/events/intel.claim.v1.avsc in the schema
registry, produce a Claim through Kafka wire format, consume it back,
assert field-for-field equality. Skips without a reachable backbone.

Env: TRUVO_KAFKA_BOOTSTRAP (e.g. localhost:9092),
     TRUVO_SCHEMA_REGISTRY (e.g. http://localhost:18081)
"""

import json
import os
import uuid
from pathlib import Path

import pytest

BOOTSTRAP = os.environ.get("TRUVO_KAFKA_BOOTSTRAP")
REGISTRY = os.environ.get("TRUVO_SCHEMA_REGISTRY")

pytestmark = pytest.mark.skipif(
    not (BOOTSTRAP and REGISTRY),
    reason="TRUVO_KAFKA_BOOTSTRAP / TRUVO_SCHEMA_REGISTRY not set",
)

CONTRACT = (
    Path(__file__).resolve().parents[4] / "contracts" / "events" / "intel.claim.v1.avsc"
)
TOPIC = "intel.claims.v1"


def sample_claim():
    return {
        "claim_id": str(uuid.uuid4()),
        "tenant": "global",
        "schema_version": "1",
        "source_id": "src-nvd",
        "provenance_id": str(uuid.uuid4()),
        "observed_at_iso": "2026-07-22T00:00:00Z",
        "raw_artifact_hash": "a" * 64,
        "extraction_model_version": "ner-v0.1.0",
        "extraction_confidence_millis": 950,
        "subject_type": "CVE",
        "subject_value": "CVE-2026-12345",
        "assertion": "observed",
        "object_value": None,
        "attack_technique_ids": ["T1190"],
    }


def test_registry_validated_roundtrip():
    from confluent_kafka import Consumer, Producer

    from truvo_events import SchemaRegistry, decode, encode

    schema = json.loads(CONTRACT.read_text(encoding="utf-8"))
    registry = SchemaRegistry(REGISTRY)

    # 1. register (idempotent) under the topic's value subject
    schema_id = registry.register("%s-value" % TOPIC, schema)
    assert schema_id > 0

    # 2. produce one claim in wire format
    claim = sample_claim()
    producer = Producer({"bootstrap.servers": BOOTSTRAP})
    producer.produce(TOPIC, value=encode(schema, schema_id, claim), key=claim["claim_id"])
    assert producer.flush(10) == 0, "message not delivered"

    # 3. consume it back and decode via the registry
    group = "roundtrip-%s" % uuid.uuid4().hex[:8]
    consumer = Consumer(
        {
            "bootstrap.servers": BOOTSTRAP,
            "group.id": group,
            "auto.offset.reset": "earliest",
        }
    )
    consumer.subscribe([TOPIC])
    got = None
    for _ in range(40):  # up to ~20s
        msg = consumer.poll(0.5)
        if msg is None or msg.error():
            continue
        try:
            decoded_id, record = decode(msg.value(), registry.get_schema)
        except Exception:
            continue  # shared dev topic may hold poison from DLQ tests
        if record["claim_id"] == claim["claim_id"]:
            got = (decoded_id, record)
            break
    consumer.close()

    assert got is not None, "produced claim never consumed"
    decoded_id, record = got
    assert decoded_id == schema_id
    assert record == claim  # field-for-field: schema round-trips losslessly

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
    import time

    from confluent_kafka import Consumer, Producer, TopicPartition
    from truvo_events import SchemaRegistry, decode, encode

    schema = json.loads(CONTRACT.read_text(encoding="utf-8"))
    registry = SchemaRegistry(REGISTRY)

    # 1. register (idempotent) under the topic's value subject
    schema_id = registry.register("%s-value" % TOPIC, schema)
    assert schema_id > 0

    # 2. produce one claim, capturing the EXACT partition+offset from the
    # delivery report. Deterministic in every environment: no dependence on
    # earliest (defeated by the shared dev topic's backlog) or latest
    # (races topic creation on a fresh CI broker).
    claim = sample_claim()
    delivered = {}

    def _on_delivery(err, msg):
        if err is None:
            delivered["tp"] = TopicPartition(TOPIC, msg.partition(), msg.offset())

    producer = Producer({"bootstrap.servers": BOOTSTRAP})
    producer.produce(
        TOPIC, value=encode(schema, schema_id, claim), key=claim["claim_id"],
        on_delivery=_on_delivery,
    )
    assert producer.flush(10) == 0, "message not delivered"
    assert "tp" in delivered, "no delivery report"

    # 3. read starting exactly at our message's offset
    consumer = Consumer({
        "bootstrap.servers": BOOTSTRAP,
        "group.id": "roundtrip-%s" % uuid.uuid4().hex[:8],
        "enable.auto.commit": False,
    })
    consumer.assign([delivered["tp"]])
    got = None
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        msg = consumer.poll(0.5)
        if msg is None or msg.error():
            continue
        try:
            decoded_id, record = decode(msg.value(), registry.get_schema)
        except Exception:
            continue
        if record["claim_id"] == claim["claim_id"]:
            got = (decoded_id, record)
            break
    consumer.close()

    assert got is not None, "produced claim never consumed"
    decoded_id, record = got
    assert decoded_id == schema_id
    assert record == claim  # field-for-field: schema round-trips losslessly

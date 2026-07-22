"""Dead-letter path live: poison in -> DLQ out, with error headers.

Env: TRUVO_TEST_DATABASE_URL + TRUVO_KAFKA_BOOTSTRAP + TRUVO_SCHEMA_REGISTRY.
"""

import os
import uuid

import pytest

ADMIN_URL = os.environ.get("TRUVO_TEST_DATABASE_URL")
KAFKA = os.environ.get("TRUVO_KAFKA_BOOTSTRAP")
REGISTRY = os.environ.get("TRUVO_SCHEMA_REGISTRY")

pytestmark = pytest.mark.skipif(
    not (ADMIN_URL and KAFKA and REGISTRY),
    reason="live env not set",
)

if ADMIN_URL:
    os.environ.setdefault(
        "TRUVO_PROVENANCE_DB_URL",
        "postgresql://truvo_app:truvo-app-dev-only@localhost:5432/truvo",
    )


def test_poison_message_lands_in_dlq():
    from confluent_kafka import Consumer, Producer

    from app.consumer import DLQ_TOPIC, TOPIC, consume_batch

    marker = ("poison-%s" % uuid.uuid4().hex[:12]).encode()
    producer = Producer({"bootstrap.servers": KAFKA})
    # not wire format at all — undecodable garbage with a traceable key
    producer.produce(TOPIC, value=b"\xff" + marker, key=marker)
    assert producer.flush(10) == 0

    consume_batch(max_messages=1000, timeout_s=15.0,
                  group="dlq-test-%s" % uuid.uuid4().hex[:8])

    dlq = Consumer(
        {
            "bootstrap.servers": KAFKA,
            "group.id": "dlq-read-%s" % uuid.uuid4().hex[:8],
            "auto.offset.reset": "earliest",
        }
    )
    dlq.subscribe([DLQ_TOPIC])
    found = None
    for _ in range(40):
        msg = dlq.poll(0.5)
        if msg is None or msg.error():
            continue
        if msg.key() == marker:
            found = msg
            break
    dlq.close()

    assert found is not None, "poison message never reached the DLQ"
    headers = dict(found.headers() or [])
    assert headers["source_topic"] == TOPIC.encode()
    assert "error" in headers and "detail" in headers
    assert found.value() == b"\xff" + marker  # original bytes preserved

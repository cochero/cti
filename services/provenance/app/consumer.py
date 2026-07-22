"""intel.claims.v1 consumer — the backbone's first real consumer.

At-least-once delivery; ingest is idempotent on claim_id (ON CONFLICT DO
NOTHING), so redelivery is harmless. The event's `tenant` field is
'global' for shared intel and is not persisted here — the claims table is
global infrastructure (db/migrations/0005); tenant-scoped enrichment
happens downstream at scoring time.

Run once per batch (cron/loop is deployment's choice):
    python -m app.consumer  # env: TRUVO_KAFKA_BOOTSTRAP, TRUVO_SCHEMA_REGISTRY
"""

import os
from typing import Optional

from confluent_kafka import Consumer, Producer

from app.main import ClaimIn, ingest_claim
from truvo_events import SchemaRegistry, decode

TOPIC = "intel.claims.v1"
DLQ_TOPIC = TOPIC + ".dlq"
GROUP = "provenance-svc"

_EVENT_ONLY_FIELDS = {"tenant", "schema_version"}


def consume_batch(
    max_messages: int = 100,
    timeout_s: float = 10.0,
    group: Optional[str] = None,
) -> int:
    """Poll up to max_messages (or until timeout_s of quiet); returns count
    ingested. Offsets commit only after successful ingest of the batch."""
    registry = SchemaRegistry(os.environ["TRUVO_SCHEMA_REGISTRY"])
    consumer = Consumer(
        {
            "bootstrap.servers": os.environ["TRUVO_KAFKA_BOOTSTRAP"],
            "group.id": group or GROUP,
            "auto.offset.reset": "earliest",
            "enable.auto.commit": False,
        }
    )
    consumer.subscribe([TOPIC])
    ingested = 0
    skipped = 0
    last_error: Optional[Exception] = None
    dlq: Optional[Producer] = None
    try:
        quiet = 0.0
        while ingested < max_messages and quiet < timeout_s:
            msg = consumer.poll(0.5)
            if msg is None:
                quiet += 0.5
                continue
            if msg.error():
                continue
            quiet = 0.0
            try:
                _schema_id, record = decode(msg.value(), registry.get_schema)
                payload = {
                    k: v for k, v in record.items() if k not in _EVENT_ONLY_FIELDS
                }
                ingest_claim(ClaimIn(**payload))
                ingested += 1
            except Exception as exc:  # poison message: dead-letter, never wedge
                skipped += 1
                last_error = exc
                if dlq is None:
                    dlq = Producer(
                        {"bootstrap.servers": os.environ["TRUVO_KAFKA_BOOTSTRAP"]}
                    )
                dlq.produce(
                    DLQ_TOPIC,
                    value=msg.value(),
                    key=msg.key(),
                    headers={
                        "error": type(exc).__name__.encode(),
                        "detail": str(exc)[:512].encode(),
                        "source_topic": TOPIC.encode(),
                    },
                )
        if dlq is not None:
            dlq.flush(10)  # dead-letters durable BEFORE offsets commit
        if ingested or skipped:
            consumer.commit()
    finally:
        consumer.close()
    if skipped:
        print("consumer: dead-lettered %d poison message(s); last error: %r"
              % (skipped, last_error))
    return ingested


if __name__ == "__main__":
    print("ingested %d claim(s)" % consume_batch())

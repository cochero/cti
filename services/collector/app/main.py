"""collector-svc — run collectors, store artifacts, emit rawdoc events.

Flow per collected doc: content-address into the object store (idempotent),
then emit intel.rawdoc.v1 onto the backbone. The raw bytes are never in
the event — only the verifiable pointer (§5.2). extraction-svc consumes
downstream.

Idempotency: the object key IS the content hash, so re-collecting the same
artifact is a no-op in storage and produces a rawdoc whose rawdoc_id is
derived from (source_id, artifact_sha256) — replaying a collection run
does not create duplicate logical documents.
"""

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from confluent_kafka import Producer

from app.collectors import Collector
from truvo_events import SchemaRegistry, encode
from truvo_objstore import ObjectStore

TOPIC = "intel.rawdoc.v1"
_CONTRACT = (
    Path(__file__).resolve().parents[3]
    / "contracts" / "events" / "intel.rawdoc.v1.avsc"
)

# rawdoc_id is a deterministic UUIDv5 of (source, content hash): stable
# across re-collection so downstream dedup is trivial.
_NS = uuid.UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8")


def _rawdoc_id(source_id: str, sha: str) -> str:
    return str(uuid.uuid5(_NS, "%s:%s" % (source_id, sha)))


class CollectorRunner:
    def __init__(self, store: Optional[ObjectStore] = None,
                 registry: Optional[SchemaRegistry] = None,
                 producer: Optional[Producer] = None,
                 bucket: str = "truvo-raw"):
        self._store = store or ObjectStore(bucket=bucket)
        self._registry = registry or SchemaRegistry(
            os.environ["TRUVO_SCHEMA_REGISTRY"]
        )
        self._producer = producer or Producer(
            {"bootstrap.servers": os.environ["TRUVO_KAFKA_BOOTSTRAP"]}
        )
        self._schema = json.loads(_CONTRACT.read_text(encoding="utf-8"))
        self._schema_id = self._registry.register("%s-value" % TOPIC, self._schema)

    def run(self, collector: Collector) -> Dict[str, Any]:
        collected = 0
        rawdoc_ids = []
        for doc in collector.collect():
            key, size = self._store.put(doc.content, content_type=doc.content_type)
            sha = hashlib.sha256(doc.content).hexdigest()  # == key
            rid = _rawdoc_id(collector.source_id, sha)
            event = {
                "rawdoc_id": rid,
                "schema_version": "1",
                "source_id": collector.source_id,
                "collected_at_iso": datetime.now(timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%S.%fZ"
                ),
                "artifact_bucket": self._store.bucket,
                "artifact_key": key,
                "artifact_sha256": sha,
                "content_type": doc.content_type,
                "content_bytes": size,
                "trust_class": collector.trust_class,
                "origin_url": doc.origin_url,
            }
            self._producer.produce(
                TOPIC, value=encode(self._schema, self._schema_id, event), key=rid
            )
            rawdoc_ids.append(rid)
            collected += 1
        self._producer.flush(15)
        return {"source_id": collector.source_id, "collected": collected,
                "rawdoc_ids": rawdoc_ids}

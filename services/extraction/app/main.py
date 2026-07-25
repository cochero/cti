"""extraction-svc — rawdoc -> extract -> gate -> claim (Architecture v2 §6.1).

Per rawdoc: fetch the artifact (self-verifying content hash), pull text,
run the extractor (stochastic), pass every candidate through the schema
gate (deterministic), and emit only ACCEPTED candidates as intel.claim.v1
events. Rejected candidates are counted and logged, never emitted.

The claim's raw_artifact_hash points back to the exact bytes extracted
from — so any claim is auditable to its evidence, and re-extraction with a
better model is always possible (§5.2).

Claims flow to provenance-svc, which applies the §7.3 corroboration floor.
extraction has no authority to make anything action-eligible; it only
proposes.
"""

import json
import os
import uuid
from typing import Any, Dict, List, Optional

from confluent_kafka import Consumer, Producer
from truvo_events import SchemaRegistry, decode, encode
from truvo_objstore import ObjectStore

from app.extractors import Extractor
from app.gate import gate_candidates

RAWDOC_TOPIC = "intel.rawdoc.v1"
CLAIM_TOPIC = "intel.claims.v1"
GROUP = "extraction-svc"

_NS = uuid.UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8")


def _text_from_artifact(data: bytes, content_type: str) -> str:
    """Extract plain text from an artifact. JSON is flattened to its string
    values; everything else is decoded as UTF-8 (lossy). HTML stripping and
    richer parsers arrive with the scraper collectors."""
    if content_type == "application/json":
        try:
            obj = json.loads(data)
        except json.JSONDecodeError:
            return data.decode("utf-8", "replace")
        parts: List[str] = []

        def walk(o):
            if isinstance(o, str):
                parts.append(o)
            elif isinstance(o, dict):
                for v in o.values():
                    walk(v)
            elif isinstance(o, list):
                for v in o:
                    walk(v)

        walk(obj)
        return "\n".join(parts)
    return data.decode("utf-8", "replace")


class ExtractionPipeline:
    def __init__(self, extractor: Extractor,
                 store: Optional[ObjectStore] = None,
                 registry: Optional[SchemaRegistry] = None,
                 producer: Optional[Producer] = None):
        self._extractor = extractor
        self._store = store  # created lazily per-bucket from the event
        self._stores: Dict[str, ObjectStore] = {}
        self._registry = registry or SchemaRegistry(
            os.environ["TRUVO_SCHEMA_REGISTRY"]
        )
        self._producer = producer or Producer(
            {"bootstrap.servers": os.environ["TRUVO_KAFKA_BOOTSTRAP"]}
        )
        from pathlib import Path

        contract = (
            Path(__file__).resolve().parents[3]
            / "contracts" / "events" / "intel.claim.v1.avsc"
        )
        self._claim_schema = json.loads(contract.read_text(encoding="utf-8"))
        self._claim_schema_id = self._registry.register(
            "%s-value" % CLAIM_TOPIC, self._claim_schema
        )

    def _store_for(self, bucket: str) -> ObjectStore:
        if self._store is not None:
            return self._store
        if bucket not in self._stores:
            self._stores[bucket] = ObjectStore(bucket=bucket)
        return self._stores[bucket]

    def process_rawdoc(self, rawdoc: Dict[str, Any]) -> Dict[str, int]:
        store = self._store_for(rawdoc["artifact_bucket"])
        data = store.get(rawdoc["artifact_key"])  # self-verifying
        text = _text_from_artifact(data, rawdoc["content_type"])

        candidates = self._extractor.extract(text)
        gated = gate_candidates(candidates)

        for cand in gated.accepted:
            claim_id = str(uuid.uuid5(
                _NS, "%s:%s:%s" % (rawdoc["rawdoc_id"], cand["subject_type"],
                                   cand["subject_value"])
            ))
            event = {
                "claim_id": claim_id,
                "tenant": "global",
                "schema_version": "1",
                "source_id": rawdoc["source_id"],
                "provenance_id": rawdoc["rawdoc_id"],
                "observed_at_iso": rawdoc["collected_at_iso"],
                "raw_artifact_hash": rawdoc["artifact_sha256"],
                "extraction_model_version": self._extractor.model_version,
                "extraction_confidence_millis": cand["extraction_confidence_millis"],
                "subject_type": cand["subject_type"],
                "subject_value": cand["subject_value"],
                "assertion": cand["assertion"],
                "object_value": cand.get("object_value"),
                "attack_technique_ids": cand.get("attack_technique_ids", []),
            }
            self._producer.produce(
                CLAIM_TOPIC,
                value=encode(self._claim_schema, self._claim_schema_id, event),
                key=claim_id,
            )
        self._producer.flush(15)
        return {"accepted": len(gated.accepted), "rejected": len(gated.rejected)}

    def consume_batch(self, max_messages: int = 100, timeout_s: float = 10.0,
                      group: Optional[str] = None) -> Dict[str, int]:
        import time as _time

        registry_url = os.environ["TRUVO_SCHEMA_REGISTRY"]
        rawdoc_registry = SchemaRegistry(registry_url)
        consumer = Consumer({
            "bootstrap.servers": os.environ["TRUVO_KAFKA_BOOTSTRAP"],
            "group.id": group or GROUP,
            "auto.offset.reset": "earliest",
            "enable.auto.commit": False,
        })
        assigned = [False]
        consumer.subscribe(
            [RAWDOC_TOPIC], on_assign=lambda c, p: assigned.__setitem__(0, True)
        )
        processed = accepted = rejected = 0
        started = _time.monotonic()
        try:
            quiet = 0.0
            while processed < max_messages and quiet < timeout_s:
                if _time.monotonic() - started > 300:
                    break
                msg = consumer.poll(0.5)
                if msg is None:
                    if assigned[0]:
                        quiet += 0.5
                    continue
                if msg.error():
                    continue
                quiet = 0.0
                try:
                    _sid, rawdoc = decode(msg.value(), rawdoc_registry.get_schema)
                    counts = self.process_rawdoc(rawdoc)
                    accepted += counts["accepted"]
                    rejected += counts["rejected"]
                    processed += 1
                except Exception:
                    # a bad rawdoc must not wedge the batch; DLQ wiring
                    # mirrors provenance (S5) and lands with the HTTP service
                    pass
            if processed:
                consumer.commit()
        finally:
            consumer.close()
        return {"processed": processed, "accepted": accepted, "rejected": rejected}

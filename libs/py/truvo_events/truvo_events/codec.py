"""Confluent wire format codec: magic byte 0x00 + schema id (BE u32) + Avro binary.

Every event on the backbone is encoded this way (contracts/README.md), so
any Confluent-ecosystem consumer — ours or a customer integration — can
decode with just registry access.
"""

import io
import struct
from typing import Any, Dict, Tuple

from fastavro import schemaless_reader, schemaless_writer

__all__ = ["encode", "decode"]

_MAGIC = 0


def encode(schema: Dict[str, Any], schema_id: int, record: Dict[str, Any]) -> bytes:
    buf = io.BytesIO()
    buf.write(struct.pack(">bI", _MAGIC, schema_id))
    schemaless_writer(buf, schema, record)
    return buf.getvalue()


def decode(payload: bytes, get_schema) -> Tuple[int, Dict[str, Any]]:
    """Decode a wire-format message. `get_schema(schema_id) -> schema dict`
    (pass SchemaRegistry.get_schema, or a cache wrapper around it)."""
    buf = io.BytesIO(payload)
    magic, schema_id = struct.unpack(">bI", buf.read(5))
    if magic != _MAGIC:
        raise ValueError("unknown wire-format magic byte %d" % magic)
    schema = get_schema(schema_id)
    return schema_id, schemaless_reader(buf, schema)

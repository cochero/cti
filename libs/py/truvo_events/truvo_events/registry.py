"""Minimal Confluent-compatible schema registry client.

Deliberately small: register + fetch, subject naming `<topic>-value`,
BACKWARD compatibility is configured registry-side (contracts/README.md).
Works against Redpanda's built-in registry and Confluent SR alike.
"""

import json
from typing import Any, Dict

import requests

__all__ = ["SchemaRegistry"]

_HEADERS = {"Content-Type": "application/vnd.schemaregistry.v1+json"}


class SchemaRegistry:
    def __init__(self, base_url: str, timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def register(self, subject: str, schema: Dict[str, Any]) -> int:
        """Register a schema under a subject; returns the global schema id.
        Idempotent: re-registering an identical schema returns the same id."""
        resp = requests.post(
            "%s/subjects/%s/versions" % (self.base_url, subject),
            data=json.dumps({"schema": json.dumps(schema)}),
            headers=_HEADERS,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()["id"]

    def get_schema(self, schema_id: int) -> Dict[str, Any]:
        resp = requests.get(
            "%s/schemas/ids/%d" % (self.base_url, schema_id), timeout=self.timeout
        )
        resp.raise_for_status()
        return json.loads(resp.json()["schema"])

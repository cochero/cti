"""SIEM/EDR push adapters (Architecture v2 §4.2 Integration Gateway).

Each adapter pushes an approved action to one customer platform. The
adapter interface is uniform; only the wire protocol differs. Credentials
arrive as already-resolved values (the service resolves them from the vault
per push — never stored here, never logged).

SplunkAdapter / SentinelAdapter are written against their HTTP APIs but are
NOT verified against a live tenant instance (no SIEM in dev) — same honest
boundary as EntraProvider. FakeAdapter drives all tests and records pushes.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol

__all__ = ["PushResult", "SiemAdapter", "FakeAdapter", "SplunkAdapter",
           "SentinelAdapter", "adapter_for"]


@dataclass(frozen=True)
class PushResult:
    ok: bool
    detail: str


class SiemAdapter(Protocol):
    name: str

    def push(self, action_type: str, target: str, creds: Dict[str, str]) -> PushResult:
        ...


@dataclass
class FakeAdapter:
    name: str = "fake"
    pushed: List[Dict[str, Any]] = field(default_factory=list)

    def push(self, action_type: str, target: str, creds: Dict[str, str]) -> PushResult:
        # records the push; asserts creds were supplied (proves vault resolution)
        if not creds.get("token"):
            return PushResult(False, "missing credential")
        self.pushed.append({"action_type": action_type, "target": target})
        return PushResult(True, "recorded by fake adapter")


class SplunkAdapter:
    """Splunk HEC push. NOT live-verified."""
    name = "splunk"

    def __init__(self, timeout: float = 15.0):
        self._timeout = timeout

    def push(self, action_type: str, target: str, creds: Dict[str, str]) -> PushResult:
        import requests
        resp = requests.post(
            "%s/services/collector/event" % creds["url"].rstrip("/"),
            headers={"Authorization": "Splunk %s" % creds["token"]},
            json={"event": {"truvo_action": action_type, "target": target}},
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return PushResult(True, "splunk %d" % resp.status_code)


class SentinelAdapter:
    """Microsoft Sentinel / Log Analytics push. NOT live-verified."""
    name = "sentinel"

    def __init__(self, timeout: float = 15.0):
        self._timeout = timeout

    def push(self, action_type: str, target: str, creds: Dict[str, str]) -> PushResult:
        import requests
        resp = requests.post(
            creds["dce_uri"],
            headers={"Authorization": "Bearer %s" % creds["token"],
                     "Content-Type": "application/json"},
            json=[{"TimeGenerated": None, "TruvoAction": action_type, "Target": target}],
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return PushResult(True, "sentinel %d" % resp.status_code)


_REGISTRY = {a.name: a for a in (FakeAdapter(), SplunkAdapter, SentinelAdapter)}


def adapter_for(name: str) -> Optional[SiemAdapter]:
    a = _REGISTRY.get(name)
    if a is None:
        return None
    return a if not isinstance(a, type) else a()

"""Collectors — acquisition sources (Architecture v2 §4 Collection Layer).

Each collector yields CollectedDoc(raw bytes + content type + origin). The
service (main.py) stores and emits; collectors never store or emit
themselves — separation keeps them dumb and individually sandboxable
(threat T2: a collector parsing hostile input is blast-radius-contained).

NVDCollector speaks the NVD 2.0 CVE API (structured JSON — low-risk
class). Scrapers of untrusted HTML/dark-web forums arrive later and MUST
run in the no-egress sandbox; they are deliberately not in this first cut.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Protocol

import requests

__all__ = ["CollectedDoc", "Collector", "NVDCollector", "FakeCollector"]


@dataclass(frozen=True)
class CollectedDoc:
    content: bytes
    content_type: str
    origin_url: Optional[str] = None
    meta: Dict[str, Any] = field(default_factory=dict)


class Collector(Protocol):
    source_id: str
    trust_class: str

    def collect(self) -> Iterable[CollectedDoc]: ...


class NVDCollector:
    """NIST NVD 2.0 CVE feed. One CollectedDoc per CVE (canonical JSON),
    so each vuln is independently content-addressed and re-extractable."""

    source_id = "src-nvd"
    trust_class = "VENDOR_ADVISORY"  # NVD is authoritative

    def __init__(self, results_per_page: int = 50, api_key: Optional[str] = None,
                 base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0",
                 timeout: float = 30.0):
        self._rpp = results_per_page
        self._api_key = api_key
        self._base = base_url
        self._timeout = timeout

    def collect(self) -> Iterable[CollectedDoc]:
        import json

        headers = {"apiKey": self._api_key} if self._api_key else {}
        resp = requests.get(
            self._base, params={"resultsPerPage": self._rpp},
            headers=headers, timeout=self._timeout,
        )
        resp.raise_for_status()
        for item in resp.json().get("vulnerabilities", []):
            cve = item.get("cve", {})
            # canonical bytes so identical CVE state addresses identically
            content = json.dumps(cve, sort_keys=True, separators=(",", ":")).encode()
            yield CollectedDoc(
                content=content,
                content_type="application/json",
                origin_url="%s?cveId=%s" % (self._base, cve.get("id", "")),
                meta={"cve_id": cve.get("id", "")},
            )


class FakeCollector:
    """Deterministic test double."""

    def __init__(self, docs: List[CollectedDoc], source_id: str = "src-fake",
                 trust_class: str = "OSINT"):
        self._docs = docs
        self.source_id = source_id
        self.trust_class = trust_class

    def collect(self) -> Iterable[CollectedDoc]:
        return list(self._docs)

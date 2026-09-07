"""Collectors — acquisition sources (Architecture v2 §4 Collection Layer).

Each collector yields CollectedDoc(raw bytes + content type + origin). The
service (main.py) stores and emits; collectors never store or emit
themselves — separation keeps them dumb and individually sandboxable
(threat T2: a collector parsing hostile input is blast-radius-contained).

NVDCollector speaks the NVD 2.0 CVE API (structured JSON — low-risk
class). Scrapers of untrusted HTML/dark-web forums arrive later and MUST
run in the no-egress sandbox; they are deliberately not in this first cut.
"""

import json
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Protocol

import requests

__all__ = ["CollectedDoc", "Collector", "NVDCollector", "KEVCollector",
           "EPSSCollector", "ATTACKSTIXCollector", "FakeCollector"]


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


def _canonical(obj: Any) -> bytes:
    """Deterministic bytes so identical feed state content-addresses
    identically across runs (the object key IS the content hash)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


class KEVCollector:
    """CISA Known Exploited Vulnerabilities catalog.

    One CollectedDoc per KEV entry (canonical JSON), so each catalog entry
    is independently content-addressed: re-collecting an unchanged catalog
    is a storage no-op, and a changed entry re-extracts cleanly. CISA is
    authoritative — the strongest 'exploited in the wild' signal that
    exists, and the highest-weight input to scoring's exploit_maturity.

    Feed: https://www.cisa.gov/information-and-analysis/itar/known-exploited-vulnerabilities-catalog
    """

    source_id = "src-cisa-kev"
    trust_class = "CERT"

    def __init__(self, base_url: str = (
            "https://www.cisa.gov/sites/default/files/feeds/"
            "known_exploited_vulnerabilities.json"),
            fetch=None, timeout: float = 30.0):
        self._base = base_url
        self._fetch = fetch or (lambda url, **kw: requests.get(url, **kw))
        self._timeout = timeout

    def collect(self) -> Iterable[CollectedDoc]:
        resp = self._fetch(self._base, timeout=self._timeout)
        resp.raise_for_status()
        catalog = resp.json()
        for entry in catalog.get("vulnerabilities", []):
            cve = entry.get("cveID", "")
            yield CollectedDoc(
                content=_canonical(entry),
                content_type="application/json",
                origin_url=self._base,
                meta={"cve_id": cve, "kev": True,
                      "date_added": entry.get("dateAdded", "")},
            )


class EPSSCollector:
    """FIRST EPSS scores — exploit probability per CVE.

    Pages through the EPSS API ordered by score (highest first), one
    CollectedDoc per CVE. The top pages carry nearly all of the scoring
    signal: EPSS is a heavy-tailed distribution, and the exploitation
    mass concentrates in the first few thousand CVEs.

    Feed: https://api.first.org/data/v1/epss (FIRST / Cybo-Rank model).
    """

    source_id = "src-first-epss"
    trust_class = "VENDOR_ADVISORY"  # authoritative structured scoring data

    def __init__(self, pages: int = 1, page_size: int = 1000,
                 base_url: str = "https://api.first.org/data/v1/epss",
                 fetch=None, timeout: float = 30.0):
        self._pages = max(1, pages)
        self._page_size = max(1, min(page_size, 1000))  # API hard cap
        self._base = base_url
        self._fetch = fetch or (lambda url, **kw: requests.get(url, **kw))
        self._timeout = timeout

    def collect(self) -> Iterable[CollectedDoc]:
        for page in range(self._pages):
            resp = self._fetch(
                self._base,
                params={
                    "scope": "all",
                    "order": "!epss",          # highest score first
                    "limit": self._page_size,
                    "offset": page * self._page_size,
                },
                timeout=self._timeout,
            )
            resp.raise_for_status()
            items = resp.json().get("data", [])
            if not items:
                return  # exhausted the catalog; stop paging
            for item in items:
                yield CollectedDoc(
                    content=_canonical(item),
                    content_type="application/json",
                    origin_url="%s?cve=%s" % (self._base, item.get("cve", "")),
                    meta={"cve_id": item.get("cve", ""),
                          "epss": item.get("epss", "")},
                )


class ATTACKSTIXCollector:
    """MITRE ATT&CK enterprise STIX bundle — techniques and threat groups.

    One CollectedDoc per STIX SDO (canonical JSON subset: only the fields
    extraction needs). Feeds both the ATT&CK heatmap (technique names,
    kill-chain phases) and actor-claims (group names + aliases) that
    entity-resolution later clusters. Deprecated/revoked objects are
    skipped: they are tombstones, not intelligence.

    Feed: https://github.com/mitre-attack/attack-stix-data (STIX 2.1
    bundle; successor location of MITRE-CTI/enterprise-attack).
    """

    source_id = "src-mitre-attack"
    trust_class = "VENDOR_ADVISORY"

    _WANT_TYPES = ("attack-pattern", "intrusion-set")

    def __init__(self, base_url: str = (
            "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
            "master/enterprise-attack/enterprise-attack.json"),
            fetch=None, timeout: float = 60.0):
        self._base = base_url
        self._fetch = fetch or (lambda url, **kw: requests.get(url, **kw))
        self._timeout = timeout

    @staticmethod
    def _slim(sdo: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Project an SDO down to the fields extraction consumes. Canonical
        bytes over the projection, not the raw bundle (which carries
        megabytes of relationship objects and churns every revision)."""
        obj = {
            "type": sdo.get("type"),
            "id": sdo.get("id"),
            "name": sdo.get("name", ""),
        }
        if sdo.get("type") == "attack-pattern":
            ext = sdo.get("x_mitre_detection", "")  # keep presence only
            obj["external_id"] = next(
                (r["external_id"] for r in sdo.get("external_references", [])
                 if r.get("source_name") == "mitre-attack"
                 and r.get("external_id")),
                "",
            )
            obj["kill_chain_phases"] = [
                {"kill_chain_name": p.get("kill_chain_name", ""),
                 "phase_name": p.get("phase_name", "")}
                for p in sdo.get("kill_chain_phases", [])
            ]
            obj["deprecated"] = bool(sdo.get("x_mitre_deprecated", False))
            obj["revoked"] = bool(sdo.get("revoked", False))
            if ext:
                obj["has_detection_guidance"] = True
        elif sdo.get("type") == "intrusion-set":
            obj["aliases"] = list(sdo.get("aliases", []))
            obj["revoked"] = bool(sdo.get("revoked", False))
        return obj

    def collect(self) -> Iterable[CollectedDoc]:
        resp = self._fetch(self._base, timeout=self._timeout)
        resp.raise_for_status()
        bundle = resp.json()
        for sdo in bundle.get("objects", []):
            if sdo.get("type") not in self._WANT_TYPES:
                continue
            if sdo.get("x_mitre_deprecated") or sdo.get("revoked"):
                continue
            slim = self._slim(sdo)
            if slim is None or not slim.get("name"):
                continue
            yield CollectedDoc(
                content=_canonical(slim),
                content_type="application/json",
                origin_url=self._base,
                meta={"stix_id": slim["id"],
                      "object_type": slim["type"]},
            )

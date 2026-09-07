"""Unit tests for the structured-feed collectors (KEV, EPSS, ATT&CK STIX).

No network: each collector gets a fetch() double serving canned feed JSON.
The properties that matter:
  - one CollectedDoc per feed item, canonical bytes (stable content hash)
  - correct source_id / trust_class for the provenance registry
  - deprecated/revoked ATT&CK objects never yield documents
  - EPSS paging stops when the feed is exhausted
  - identical feed state -> identical bytes -> identical content address
    (idempotent re-collection is a platform invariant, not a hope)
"""

import hashlib
import json
from pathlib import Path

import pytest
from app.collectors import ATTACKSTIXCollector, EPSSCollector, KEVCollector

FIXTURES = Path(__file__).parent / "fixtures"


class FetchDouble:
    """requests-like double over a canned payload."""

    def __init__(self, payload):
        self._payload = payload
        self.calls = []

    def __call__(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


def _fixture(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class TestKEVCollector:
    def test_one_doc_per_entry_with_canonical_bytes(self):
        fetch = FetchDouble(_fixture("kev_sample.json"))
        docs = list(KEVCollector(fetch=fetch).collect())

        assert len(docs) == 3
        cves = [d.meta["cve_id"] for d in docs]
        assert cves == ["CVE-2021-44228", "CVE-2023-23397", "CVE-2024-3400"]
        for doc in docs:
            assert doc.content_type == "application/json"
            parsed = json.loads(doc.content)
            assert parsed["cveID"] == doc.meta["cve_id"]
            # canonical: sorted keys, compact separators
            assert doc.content == json.dumps(
                parsed, sort_keys=True, separators=(",", ":")).encode()

    def test_source_identity(self):
        c = KEVCollector(fetch=FetchDouble(_fixture("kev_sample.json")))
        assert c.source_id == "src-cisa-kev"
        assert c.trust_class == "CERT"

    def test_identical_state_identical_hash(self):
        fetch = FetchDouble(_fixture("kev_sample.json"))
        h1 = [hashlib.sha256(d.content).hexdigest()
              for d in KEVCollector(fetch=fetch).collect()]
        h2 = [hashlib.sha256(d.content).hexdigest()
              for d in KEVCollector(fetch=fetch).collect()]
        assert h1 == h2


class TestEPSSCollector:
    def test_one_doc_per_cve_ordered(self):
        fetch = FetchDouble(_fixture("epss_sample.json"))
        docs = list(EPSSCollector(pages=1, fetch=fetch).collect())

        assert len(docs) == 4
        assert docs[0].meta["cve_id"] == "CVE-2024-3400"  # highest epss first
        assert docs[0].meta["epss"] == 0.97052
        parsed = json.loads(docs[0].content)
        assert parsed["cve"] == "CVE-2024-3400"
        assert parsed["percentile"] == 0.99985

    def test_paging_requests_offsets_and_stops_on_empty(self):
        pages_payload = {
            "status": "OK",
            "data": [{"cve": "CVE-2021-0001", "epss": 0.5, "percentile": 0.9,
                      "date": "2026-07-21"}],
            "total": 1,
        }
        empty_payload = {"status": "OK", "data": [], "total": 0}

        state = {"n": 0}

        class PagedFetch:
            def __call__(self, url, params=None, **kwargs):
                payload = pages_payload if state["n"] == 0 else empty_payload
                state["n"] += 1
                self.last_params = params
                return FetchDouble(payload)

        fetch = PagedFetch()
        docs = list(EPSSCollector(pages=5, page_size=1000, fetch=fetch).collect())
        assert len(docs) == 1  # second page empty -> stop, don't error
        assert state["n"] == 2
        assert fetch.last_params == {
            "scope": "all", "order": "!epss", "limit": 1000, "offset": 1000}

    def test_source_identity(self):
        c = EPSSCollector(fetch=FetchDouble(_fixture("epss_sample.json")))
        assert c.source_id == "src-first-epss"
        assert c.trust_class == "VENDOR_ADVISORY"


class TestATTACKSTIXCollector:
    def test_techniques_and_groups_only(self):
        fetch = FetchDouble(_fixture("attack_sample.json"))
        docs = list(ATTACKSTIXCollector(fetch=fetch).collect())

        types = sorted(d.meta["object_type"] for d in docs)
        # 2 live techniques + 1 live group; revoked + deprecated skipped
        assert types == ["attack-pattern", "attack-pattern", "intrusion-set"]

        by_stix = {d.meta["stix_id"]: json.loads(d.content) for d in docs}
        tech = by_stix["attack-pattern--b61bac06-2a0a-4f2f-9b1a-1f0d5a4f6f11"]
        assert tech["external_id"] == "T1566.001"
        assert tech["name"] == "Spearphishing Attachment"
        phases = [p["phase_name"] for p in tech["kill_chain_phases"]]
        assert phases == ["initial-access", "execution"]
        # detection guidance is projected to presence-only: the console
        # reads guidance from MITRE directly; we carry the signal, not the prose
        assert tech["has_detection_guidance"] is True
        assert "x_mitre_detection" not in tech

        group = by_stix["intrusion-set--56f1a837"]
        assert group["aliases"] == ["HIDDEN COBRA", "APT38", "Diamond Sleet"]

    def test_revoked_and_deprecated_never_collected(self):
        fetch = FetchDouble(_fixture("attack_sample.json"))
        stix_ids = {d.meta["stix_id"] for d in ATTACKSTIXCollector(fetch=fetch).collect()}
        assert "attack-pattern--deadbeef" not in stix_ids
        assert "intrusion-set--deprecated01" not in stix_ids

    def test_non_relevant_sdo_types_skipped(self):
        fetch = FetchDouble(_fixture("attack_sample.json"))
        docs = list(ATTACKSTIXCollector(fetch=fetch).collect())
        types = {d.meta["object_type"] for d in docs}
        assert "malware" not in types
        assert "identity" not in types


@pytest.mark.parametrize("collector_cls,fixture", [
    (KEVCollector, "kev_sample.json"),
    (EPSSCollector, "epss_sample.json"),
    (ATTACKSTIXCollector, "attack_sample.json"),
])
def test_all_docs_are_deterministic_bytes(collector_cls, fixture):
    """Re-parse and re-dump every collected doc: byte-identical or the
    content-addressing contract is broken."""
    fetch = FetchDouble(_fixture(fixture))
    for doc in collector_cls(fetch=fetch).collect():
        parsed = json.loads(doc.content)
        assert doc.content == json.dumps(
            parsed, sort_keys=True, separators=(",", ":")).encode()

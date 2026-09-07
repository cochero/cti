"""Real-feed collection entrypoint (structured, authoritative sources).

Runs the structured collectors — NVD, CISA KEV, FIRST EPSS, MITRE
ATT&CK — through the real CollectorRunner and prints per-source results.
These are authoritative structured feeds (low ingestion risk class);
scrapers of untrusted HTML arrive separately inside the no-egress sandbox.

    python -m app.run_feeds                      # all feeds
    python -m app.run_feeds nvd kev epss attack   # subset by key

Sources must be pre-registered in provenance-svc (source registry);
run_feeds registers them idempotently first so a fresh environment works.
"""

import json
import os
import sys
from typing import Dict

import requests

from app.collectors import ATTACKSTIXCollector, EPSSCollector, KEVCollector, NVDCollector

# provenance-svc registration payloads: Admiralty-style grade per source.
# A=authoritative primary. source_type uses the registry's sanctioned
# enum (db CHECK): nvd/epss/attack are authoritative advisories/scores,
# kev is a CERT catalog — the two classes that clear the §7.3 floor.
SOURCE_REGISTRY: Dict[str, Dict] = {
    "src-nvd": {
        "name": "NIST NVD (CVE 2.0 API)",
        "source_type": "vendor_advisory", "grade": "A",
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
    },
    "src-cisa-kev": {
        "name": "CISA Known Exploited Vulnerabilities",
        "source_type": "cert", "grade": "A",
        "url": "https://www.cisa.gov/sites/default/files/feeds/"
               "known_exploited_vulnerabilities.json",
    },
    "src-first-epss": {
        "name": "FIRST EPSS (exploit prediction scoring)",
        "source_type": "vendor_advisory", "grade": "A",
        "url": "https://api.first.org/data/v1/epss",
    },
    "src-mitre-attack": {
        "name": "MITRE ATT&CK Enterprise (STIX)",
        "source_type": "vendor_advisory", "grade": "A",
        "url": "https://raw.githubusercontent.com/mitre-attack/"
               "attack-stix-data/master/enterprise-attack/"
               "enterprise-attack.json",
    },
}


def _register_sources() -> None:
    """Idempotent source registration via provenance-svc HTTP API (the
    only sanctioned write path for the registry). Absent provenance in
    dev -> warn and continue; claims from an unregistered source are
    rejected downstream, loudly, which is the correct failure mode."""
    base = os.environ.get("TRUVO_PROVENANCE_URL")
    if not base:
        print("TRUVO_PROVENANCE_URL unset; skipping source registration",
              file=sys.stderr)
        return
    for source_id, spec in SOURCE_REGISTRY.items():
        try:
            resp = requests.post(
                "%s/v1/sources" % base.rstrip("/"), json={
                    "source_id": source_id, **spec}, timeout=15,
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            print("source registration failed for %s: %s" % (source_id, exc),
                  file=sys.stderr)


def _collectors():
    return {
        "nvd": lambda: NVDCollector(
            results_per_page=int(os.environ.get("TRUVO_NVD_RPP", "50")),
            api_key=os.environ.get("TRUVO_NVD_API_KEY"),
        ),
        "kev": lambda: KEVCollector(),
        "epss": lambda: EPSSCollector(
            pages=int(os.environ.get("TRUVO_EPSS_PAGES", "1")),
        ),
        "attack": lambda: ATTACKSTIXCollector(),
    }


def main(argv=None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    wanted = [a for a in argv if a in _collectors()]
    unknown = [a for a in argv if a not in _collectors()]
    if unknown:
        raise SystemExit("unknown feed(s) %s; known: %s"
                         % (unknown, sorted(_collectors())))
    feeds = wanted or list(_collectors())

    _register_sources()
    from app.main import CollectorRunner

    runner = CollectorRunner(
        bucket=os.environ.get("TRUVO_RAW_BUCKET", "truvo-raw"))
    results = []
    for feed in feeds:
        collector = _collectors()[feed]()
        try:
            result = runner.run(collector)
        except Exception as exc:  # one feed failing must not kill the rest
            result = {"source_id": collector.source_id, "error": str(exc)}
        results.append(result)
    print(json.dumps({"feeds": results}))


if __name__ == "__main__":
    main()

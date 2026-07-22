# collector-fleet

Sandboxed, no-privilege collectors. Phase 2 starts with 3 sources: NVD/CVE, one TAXII feed, one curated OSINT aggregator.

- **Reference:** Arch SS4.2; built Phase 2
- **Owner:** Intelligence Pipeline
- **Status:** scaffold only -- see DEVELOPMENT_PLAN.md for the sprint that builds this.

Before first staging traffic this component needs: OTel instrumentation,
a runbook in `ops/runbooks/`, and a reviewed THREAT_MODEL.md (see
`services/ledger/THREAT_MODEL.md` for the pattern).

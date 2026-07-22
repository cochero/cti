# entity-resolution-svc

Alias clustering (Lazarus = HIDDEN COBRA = APT38), IOC dedup, CPE canonicalization. Human adjudication queue for low-confidence merges.

- **Reference:** Arch SS4.2; built Phase 2
- **Owner:** Intelligence Pipeline
- **Status:** scaffold only -- see DEVELOPMENT_PLAN.md for the sprint that builds this.

Before first staging traffic this component needs: OTel instrumentation,
a runbook in `ops/runbooks/`, and a reviewed THREAT_MODEL.md (see
`services/ledger/THREAT_MODEL.md` for the pattern).

# response-orchestrator

Three-tier execution matrix + circuit breakers (velocity, blast-radius, novelty, dead-man). The ONLY service allowed to command gateway mutations. Tier 3 only at launch.

- **Reference:** Arch SS8; built Phase 4
- **Owner:** Product & Integrations
- **Status:** scaffold only -- see DEVELOPMENT_PLAN.md for the sprint that builds this.

Before first staging traffic this component needs: OTel instrumentation,
a runbook in `ops/runbooks/`, and a reviewed THREAT_MODEL.md (see
`services/ledger/THREAT_MODEL.md` for the pattern).

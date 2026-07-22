# gateway-svc

Bi-directional customer integrations (SIEM/EDR/SOAR/ticketing). Per-tenant vault partitions; refuses unsigned/replayed commands even from inside our network.

- **Reference:** Arch SS8.3; built Phase 3
- **Owner:** Product & Integrations
- **Status:** scaffold only -- see DEVELOPMENT_PLAN.md for the sprint that builds this.

Before first staging traffic this component needs: OTel instrumentation,
a runbook in `ops/runbooks/`, and a reviewed THREAT_MODEL.md (see
`services/ledger/THREAT_MODEL.md` for the pattern).

# detect-svc

Streaming IOC matching (bloom pre-screen -> exact -> graph context); credential-leak monitor scoped to customer-registered domains only.

- **Reference:** Arch SS4.2, SS11.3; built Phase 4
- **Owner:** Intelligence Pipeline
- **Status:** scaffold only -- see DEVELOPMENT_PLAN.md for the sprint that builds this.

Before first staging traffic this component needs: OTel instrumentation,
a runbook in `ops/runbooks/`, and a reviewed THREAT_MODEL.md (see
`services/ledger/THREAT_MODEL.md` for the pattern).

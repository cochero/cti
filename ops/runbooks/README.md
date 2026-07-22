# Runbooks

One runbook per service. Every alert links to its runbook page (platform DoD SS1.6). No runbook, no production traffic.

- **Reference:** standing
- **Owner:** all squads
- **Status:** scaffold only -- see DEVELOPMENT_PLAN.md for the sprint that builds this.

Before first staging traffic this component needs: OTel instrumentation,
a runbook in `ops/runbooks/`, and a reviewed THREAT_MODEL.md (see
`services/ledger/THREAT_MODEL.md` for the pattern).

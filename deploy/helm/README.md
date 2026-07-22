# Helm charts

Same charts for both profiles; Full Mesh vs Compact differ only in values files (Arch SS2.8, SS12). Charts land S5-S6 with the staging cluster.

- **Reference:** built S5-S6
- **Owner:** Platform
- **Status:** scaffold only -- see DEVELOPMENT_PLAN.md for the sprint that builds this.

Before first staging traffic this component needs: OTel instrumentation,
a runbook in `ops/runbooks/`, and a reviewed THREAT_MODEL.md (see
`services/ledger/THREAT_MODEL.md` for the pattern).

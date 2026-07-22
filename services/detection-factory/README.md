# detection-factory

Sigma-first rule compilation: author -> lint -> detonation-test -> sign -> package. Transpile targets to GA: KQL (Sentinel), SPL (Splunk).

- **Reference:** Arch SS4.2, SS9.3; built Phase 3
- **Owner:** Product & Integrations + detection engineer
- **Status:** scaffold only -- see DEVELOPMENT_PLAN.md for the sprint that builds this.

Before first staging traffic this component needs: OTel instrumentation,
a runbook in `ops/runbooks/`, and a reviewed THREAT_MODEL.md (see
`services/ledger/THREAT_MODEL.md` for the pattern).

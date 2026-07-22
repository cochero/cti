# extraction-svc

LLM/NER extraction in a no-egress sandbox; JSON-schema-constrained output only. Prompt-injection regression suite required in CI from day one.

- **Reference:** Arch SS6.1-6.2; built Phase 2
- **Owner:** Intelligence Pipeline
- **Status:** scaffold only -- see DEVELOPMENT_PLAN.md for the sprint that builds this.

Before first staging traffic this component needs: OTel instrumentation,
a runbook in `ops/runbooks/`, and a reviewed THREAT_MODEL.md (see
`services/ledger/THREAT_MODEL.md` for the pattern).

# scoring-svc

Deterministic prioritization engine: pure function over versioned inputs+weights. Every output writes a ledger entry. Ships in the same sprints as its backtesting.

- **Reference:** Arch SS6.4; built Phase 3
- **Owner:** ML & Evaluation
- **Status:** scaffold only -- see DEVELOPMENT_PLAN.md for the sprint that builds this.

Before first staging traffic this component needs: OTel instrumentation,
a runbook in `ops/runbooks/`, and a reviewed THREAT_MODEL.md (see
`services/ledger/THREAT_MODEL.md` for the pattern).

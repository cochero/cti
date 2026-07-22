# eval-harness

Backtesting, calibration (Brier/reliability), drift watch, FP economics, poisoning canaries. Owns the ground-truth store. 'Measure or remove' lives here.

- **Reference:** Arch SS9; built Phase 2-3
- **Owner:** ML & Evaluation
- **Status:** scaffold only -- see DEVELOPMENT_PLAN.md for the sprint that builds this.

Before first staging traffic this component needs: OTel instrumentation,
a runbook in `ops/runbooks/`, and a reviewed THREAT_MODEL.md (see
`services/ledger/THREAT_MODEL.md` for the pattern).

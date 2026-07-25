# eval-harness

Backtesting + calibration — "measure or remove" (Architecture v2 §9).

- **Reference:** Architecture v2 §9.2, §5.3; db/migrations/0010
- **Owner:** ML & Evaluation
- **Status:** calibration math + backtest reader live-tested

## Why it exists
The whole PREDICT story rests on this. A score of "800" is only meaningful if,
historically, ~80% of 800-band threats materialized. app/calibration.py
measures exactly that against ground truth (Brier score, reliability curve,
precision@k) so scores can be PROVEN, not asserted — and so a weights version
that doesn't beat the incumbent never ships.

## Proven (live)
- Brier (0=perfect, 1=worst), reliability bands (predicted mid vs actual rate +
  gap), precision@k over a seeded score/outcome distribution; RLS-fenced
  per-tenant backtest.

## Not yet
- The ground-truth store is empty by definition until design partners generate
  real outcomes. Metrics are correct; the data to run them on real predictions
  doesn't exist yet. Drift monitoring and automated weights-promotion gates
  build on top of this once ground truth accrues.

Before staging: OTel, runbook, THREAT_MODEL.md.

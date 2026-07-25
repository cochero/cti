# scoring-svc

Deterministic prioritization engine — the PREDICT product (Architecture v2 §6.4).

- **Reference:** Architecture v2 §6.4, §2.4; db/migrations/0010; ADR-0007
- **Owner:** ML & Evaluation
- **Status:** engine + wiring live-tested; weights-v0 (uncalibrated — see below)

## The model
`score(inputs, weights) -> ScoreResult` (app/engine.py) is a PURE, versioned,
integer-only function: same inputs + same weights -> byte-identical output,
replayable from the ledger forever. It combines six factors — stack overlap
(does the tenant run the affected product), exploit maturity (EPSS/KEV/PoC),
actor reachability (graph), identity exposure (blast radius), campaign
momentum, sector affinity — into a priority [0,1000] with a FULL decomposition
written to a hash-chained ledger entry. What it claims: calibrated RELATIVE
prioritization with a visible decomposition. What it never claims:
point-probability certainty.

## Proven (live)
- Real signals (tenant tech stack + KEV CVE + graph-reachable actor + targeted
  sector + privileged identities) -> high priority (680) with correct
  per-factor decomposition; an unaffected tenant scores far lower (relevance
  gap). Decomposition is on the ledger and tamper-evident. RLS isolates scores.

## Not yet honest to ship as PREDICT
- **weights-v0 is UNCALIBRATED.** The numbers are defensible priors, not
  validated weights. Per §9 / "measure or remove", a weights version earns
  promotion only by beating the incumbent in eval-harness backtest on real
  ground truth — which needs design-partner data. Until then scores are
  internally consistent and auditable, but their calibration is unproven.

Before staging: OTel, runbook, THREAT_MODEL.md.

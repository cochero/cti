# ADR-0008: Response guardrail model — tiers, the §7.3 action-layer floor, and hard-block vs downgrade breakers

- **Status:** Accepted
- **Date:** 2026-07-24
- **Deciders:** founding engineering team
- **Relates to:** Architecture v2 §8, §7.3, §3.1-T8; DEVELOPMENT_PLAN Phase 4

## Context
The response-orchestrator is the only service that can authorize outbound
action against a customer environment. It is the highest-blast-radius
component in the platform: a wrong autonomous action can take down
production. Its decision logic must be pure, exhaustively tested, and
encode the architecture's safety invariants as code, not prose.

## Decision
1. **The §7.3 floor is enforced at the action layer, not just at
   ingestion.** `autonomy_eligible(evidence)` returns true only for
   HIGH_TRUST_CORROBORATED or FIRST_PARTY evidence. Open-source
   intelligence — single OR corroborated — can NEVER authorize autonomous
   action, by construction. `decide_tier` routes any OSINT-backed action to
   Tier 3 (human) regardless of asset triviality or reversibility.
2. **Three-tier matrix** (`decide_tier`), hard rules in order: irreversible
   → Tier 3; CRITICAL asset/identity → Tier 3; not autonomy-eligible →
   Tier 3; NON_CRITICAL + reversible + eligible → Tier 1; else Tier 2.
3. **Two breaker kinds**, distinguished by `forced_tier`:
   - **Hard block** (`forced_tier=None`, verdict "blocked"): global spike
     (platform may be compromised — we distrust ourselves), dead-man
     (blind to effects), velocity (halt the firehose). The action is
     refused outright; not even a human is auto-looped — it must be
     re-proposed.
   - **Downgrade** (`forced_tier=TIER3`, verdict "human"): novelty (first
     use of an action type) and blast-radius (broad impact) route to a
     human instead of acting autonomously.
4. Every decision is written to a hash-chained ledger entry and an
   append-only action log; the action log is also the source of
   circuit-breaker state.
5. The global-velocity count crosses tenants (a platform-wide spike is the
   signal), so it runs through a SECURITY DEFINER function that bypasses
   RLS and returns only an aggregate integer — never any tenant's rows.

## Consequences
The guardrail unit tests are the platform's safety spec: a change that
flips any of them changes what TRUVO may do autonomously and requires a new
ADR. Costs: the hard-block breakers can refuse legitimate actions in a
spike/outage — accepted, because the failure mode of over-refusing is a
missed automation, while over-acting is a customer outage or an
attacker-delivered DoS. Revisit triggers: real incident data showing a
breaker is mis-tuned (adjust thresholds, keep the model), or a customer
requirement for per-tenant breaker thresholds above the hardcoded floors
(never below).

# response-orchestrator

The only service that can authorize outbound action — three-tier matrix + circuit breakers (Architecture v2 §8).

- **Reference:** Architecture v2 §8, §7.3, §3.1-T8; db/migrations/0012; ADR-0008
- **Owner:** Product & Integrations
- **Status:** guardrails + service live-tested; gateway push is a later, separate service

## The safety model (this is the point)
`app/guardrails.py` is PURE and exhaustively unit-tested — it IS the platform's safety spec. The §7.3 anti-weaponization floor is enforced at the ACTION layer: OSINT (single or corroborated) can NEVER authorize autonomous action; it routes to a human every time. The three-tier matrix sends irreversible actions, critical assets, and C-level identities to human review. Circuit breakers either HARD-BLOCK (global spike, dead-man, velocity — refuse outright) or DOWNGRADE to human (novelty, blast-radius). Every decision is hash-chained to the ledger and logged append-only.

## Proven (live)
- OSINT action never autonomous; first use of an action type routes through a human (novelty); critical asset forced human; dead-man switch blocks; decision on the ledger; RLS isolates; cross-tenant global breaker via SECURITY DEFINER aggregate.

## Not yet
- gateway-svc: the actual SIEM/EDR push on an 'approved' verdict, with per-tenant vaulted credentials and signed commands (§8.3). This service DECIDES; the gateway ACTS, and only on this service's approval.
- Tenant policy evaluation for Tier 2 (time windows, change-freeze calendars).

Before staging: OTel, runbook, THREAT_MODEL.md.

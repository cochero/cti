# ADR-0004: External anchoring of the audit ledger

- **Status:** Accepted (design; implementation lands S5–S6)
- **Date:** 2026-07-22
- **Deciders:** founding engineering team
- **Relates to:** Architecture v2 §3.1-T7, §4.2 ledger-svc; DEVELOPMENT_PLAN S3–S4

## Context
The hash chain makes tampering *detectable by anyone holding an honest
head hash* — but if an attacker with full DB access rewrites the entire
chain from entry k onward (recomputing every hash), the chain is
internally consistent again. Detection then depends on comparing against
a head hash stored **outside** the attacker's reach. Live tamper
detection of partial rewrites is already proven
(services/ledger/tests_live); anchoring closes the full-rewrite case.

## Decision
1. `ledger-svc` produces a signed **anchor record** per tenant on a
   schedule (default daily; configurable): `(tenant, as_of_ts, last_seq,
   head_hash, anchor_sig)`, signed with the service's per-tenant key.
2. Anchors are delivered to destinations the **customer** controls,
   chosen per deployment: an S3/MinIO WORM bucket, the customer's
   ticketing system, or plain email — anything append-only from the
   platform's perspective. Air-gapped (Compact) deployments print anchors
   into the signed offline bundle manifest.
3. `/v1/{tenant}/verify` gains an optional `?anchor=<record>` parameter:
   verification then also proves the current chain extends the anchored
   head (same hash at `last_seq`).
4. Anchor cadence and destinations are tenant configuration, not code.

## Consequences
Full-rewrite attacks become detectable with at most one cadence-window of
exposure; customers hold their own proof (compliance value: the vendor
cannot silently rewrite either). Costs: key management per tenant (rides
the S7 vault/mTLS work), and a support path for "anchor mismatch" —
which is, by definition, a sev-1 incident response, never a
reconciliation script. Revisit trigger: a customer requirement for
per-entry (not periodic) anchoring — that is a different cost class and
gets its own ADR.

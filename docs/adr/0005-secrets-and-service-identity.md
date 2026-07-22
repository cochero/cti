# ADR-0005: Secrets layer (OpenBao) and service identity (request signing now, mesh mTLS at staging)

- **Status:** Accepted
- **Date:** 2026-07-23
- **Deciders:** founding engineering team
- **Relates to:** Architecture v2 §8.3, §10, §11.1; DEVELOPMENT_PLAN S7

## Context
Through S6 the codebase carried explicit "S7 fixes this" markers: dev
passwords in env vars, the anchor key as a single shared env secret, IdP
client secrets passed raw in request bodies, and ledger-svc trusting the
caller's tenant claim. Each was acceptable scaffolding and is not
acceptable production behavior.

## Decision
1. **Secrets backend: OpenBao** (Vault-API-compatible, MPL-2.0). Same
   licensing logic as OpenSearch/Redpanda: the Compact profile
   redistributes into customer racks, so every bundled component must
   carry a permissive license. Cloud KMS/HSM backs the SaaS unseal;
   customer HSM (PKCS#11) backs Compact.
2. **Secret references, never secret values**, in config and API bodies:
   `vault:<mount>/<path>#<field>` (or `env:` in dev/test). `truvo_secrets`
   is the only resolution path. A raw secret in config or a request body
   is a review-blocking defect once a component has refs support.
3. **Per-tenant anchor keys** live at `secret/truvo/tenants/<t>#anchor_key`
   (auto-provisioned in dev; provisioned at tenant onboarding in prod;
   customer-HSM custody in Compact). Key rotation invalidates old anchors
   by design — rotation implies re-anchoring.
4. **Service identity = Ed25519 request signing** (`truvo_svcauth`):
   signatures over (svc, ts, method, path, body-hash); public keys at
   `secret/truvo/services/<svc>#pubkey`; ±300s replay window; enforcement
   env-gated per service for staged rollout (`TRUVO_SVCAUTH=1`).
5. **Transport mTLS (SPIFFE/SPIRE mesh) is a deployment-layer addition at
   staging (S8+)**, not an application code path. Request signing and
   mesh mTLS are defense in depth: app-layer identity survives mesh
   misconfiguration and vice versa.
6. Dev-mode vault (compose) uses a root token; staging/prod services
   authenticate via Kubernetes auth for short-lived tokens. Client code
   sees only a token string either way.

## Consequences
Stolen network access no longer suffices to write to the ledger; stolen
DB access was already insufficient (RLS + hash chain + anchors). Costs:
vault is now tier-0 infrastructure (its availability gates mutations —
runbook required before staging); key provisioning joins tenant
onboarding; every internal caller must adopt signing before enforcement
flips on globally. Revisit triggers: SPIFFE mesh landing (fold pubkey
distribution into SVIDs?), or a customer requirement for asymmetric
anchor signatures (Ed25519 anchors) — format change, new ADR.

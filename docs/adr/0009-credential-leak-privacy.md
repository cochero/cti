# ADR-0009: Credential-leak monitoring — domain-scoped, salted-hash-only

- **Status:** Accepted
- **Date:** 2026-07-24
- **Deciders:** founding engineering team + counsel (to review)
- **Relates to:** Architecture v2 §11.3, §4.2 Detect; DEVELOPMENT_PLAN Phase 4

## Context
Credential-leak monitoring is valuable but legally and ethically fraught: a
naive implementation warehouses the internet's stolen PII, turning TRUVO
into a breach-data broker and a high-value target. The architecture (§11.3)
is explicit: we search for the CUSTOMER's assets, we do not warehouse
everyone's stolen data, and we never persist cleartext credentials.

## Decision
1. **Domain scoping is enforced in pure code** (`app/credleak.scan_breach`),
   not in a query filter that could be forgotten. A breach record whose
   email domain is not one the customer registered (`tenant_domains`) is
   dropped before it ever reaches storage — it is never persisted, not even
   transiently.
2. **Cleartext is never stored.** The output object has no cleartext field
   by construction — only a per-tenant **salted** SHA-256 of the credential.
   A leak of TRUVO's own database therefore cannot re-leak customer
   passwords (the salt is per-tenant, in the vault).
3. **The salt is per-tenant, vault-held** (`secret/truvo/tenants/<t>#cred_salt`),
   auto-provisioned on first scan. Rotating it invalidates comparison of old
   hashes — acceptable, since the value is "was this account in a breach",
   not the credential itself.
4. **The read API exposes only the customer's own account identifiers**
   (local@registered-domain) + breach source — never credential material,
   salted or not.
5. All detect tables are tenant-RLS-fenced; `credential_leaks` is
   append-only.

## Consequences
TRUVO can tell a customer "these of YOUR accounts appeared in breach X"
without ever holding a saleable corpus of stolen credentials or a cleartext
password. Costs: we cannot answer "has this arbitrary account leaked" for
non-customers (by design); a customer must register domains before
monitoring works (surfaced in onboarding). Revisit triggers: a legal review
requiring even tighter handling (e.g. not storing local-parts), or a
customer requirement for k-anonymized breach counts — both narrow, not
widen, what is stored. The pure `scan_breach` is the enforcement point; its
tests are the privacy spec.

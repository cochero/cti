# detect-svc

Continuous monitoring: IOC streaming + credential-leak (Architecture v2 §4.2 Detect, §11.3).

- **Reference:** Architecture v2 §4.2, §11.3; db/migrations/0014; ADR-0009
- **Owner:** Intelligence Pipeline
- **Status:** IOC match + credential-leak live-tested

## Capabilities
- **IOC match** (`/v1/ioc-match`): cross-reference an inbound IOC batch against the tenant watchlist via a bloom pre-screen (no false negatives — a real IOC is never missed) then exact confirm, returning hits with graph context (which actor/malware the IOC belongs to).
- **Credential-leak** (`/v1/credential-scan`): scan a breach dump for the tenant's REGISTERED domains only (§11.3 / ADR-0009). A non-registered domain is dropped before storage; only a per-tenant salted hash is stored, never cleartext.

## Proven (live)
- Bloom no-false-negatives (unit); IOC match + graph context; credential scan surfaces only registered domains (non-customer domains dropped, never stored); cleartext never persisted (only 64-char salted hash); idempotent; RLS isolates.

## Not yet
- Real-time streaming ingestion (v0 is batch POST; the matching core is stream-ready).
- Bloom filter persisted/incremental for very large watchlists (v0 rebuilds per request).

Before staging: OTel, runbook, THREAT_MODEL.md.

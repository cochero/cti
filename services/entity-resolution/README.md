# entity-resolution-svc

Alias clustering: the Lazarus = HIDDEN COBRA = APT38 = Diamond Sleet problem (Architecture v2 §4.2).

- **Reference:** Architecture v2 §4.2; db/migrations/0008
- **Owner:** Intelligence Pipeline
- **Status:** deterministic exact-alias resolution live; fuzzy/embedding clustering deferred

## What it does
Every subject value resolves to exactly one canonical entity. CVEs canonicalize by format; names resolve by normalized exact-match against a curated alias table (seeded from real MITRE ATT&CK group aliases, app/seed_aliases.json). Unknown values auto-create a singleton canonical entity so the pipeline never stalls; adjudicated merges collapse singletons over time.

## Proven (live)
- Six Lazarus aliases -> one canonical entity; APT28/29 stay distinct; CVE canonicalizes across spellings; merge collapses singletons.
- Conservative normalization (unit-tested): over-normalization corrupts intel (wrong merge) which is worse than a missed merge (duplicate).

## Not yet
- Fuzzy / embedding-similarity clustering (needs the vector store; always routes to the adjudication queue, never auto-merges).
- IOC dedup and CPE canonicalization beyond CVEs.

Before staging: OTel, runbook, THREAT_MODEL.md.

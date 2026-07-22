# ADR-0001: Record architecture decisions as ADRs in-repo

- **Status:** Accepted
- **Date:** 2026-07-22
- **Deciders:** founding engineering team
- **Relates to:** DEVELOPMENT_PLAN §3

## Context
TRUVO_Architecture_v2.md is the architecture of record. Day-to-day engineering
will surface pressure to deviate (a library gap, a licensing surprise, a
customer demand). Undocumented deviations rot the architecture's authority.

## Decision
Every deviation from the architecture of record, and every significant new
technical decision, is recorded as an ADR in `docs/adr/`, numbered
sequentially, using the template in ADR-0000. A PR that deviates without an
ADR does not merge.

## Consequences
Slight friction on decisions (intended); a durable, greppable decision log;
onboarding engineers can reconstruct *why*, not just *what*. Revisit trigger:
if ADRs are being written after-the-fact as paperwork rather than as
decisions, the process has failed and we fix the process, not the rule.

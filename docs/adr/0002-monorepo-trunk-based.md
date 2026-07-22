# ADR-0002: Monorepo with trunk-based development

- **Status:** Accepted
- **Date:** 2026-07-22
- **Deciders:** founding engineering team
- **Relates to:** DEVELOPMENT_PLAN §3, §7

## Context
4–15 engineers, ~14 services sharing contracts and a core library, two
deployment profiles built from one codebase (Architecture §2.8). Polyrepo
would make cross-service schema changes multi-PR, multi-repo ceremonies and
make "same code, both profiles" drift-prone.

## Decision
One repository (`truvo/`), layout per DEVELOPMENT_PLAN §7. Trunk-based:
short-lived branches, mandatory PR review, `main` always deployable.
Services version together; deployment profiles differ only in
`deploy/` values.

## Consequences
Atomic cross-cutting changes; one CI pipeline enforcing the platform DoD
(signing, SBOM, leak tests, replay test) in one place. Costs: CI must stay
fast (path-filtered jobs as the repo grows); repo-wide standards must be
actively maintained. Revisit trigger: CI wall-time > 15 min on a typical PR,
or a team scaling event (>25 engineers).

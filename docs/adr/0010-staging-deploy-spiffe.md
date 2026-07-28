# ADR-0010: Staging deployment — Helm two-profile chart, GHCR images, SPIFFE mesh

- **Status:** Accepted (chart + workflow built and validated; live deploy gated on a cloud account)
- **Date:** 2026-07-24
- **Deciders:** founding engineering team
- **Relates to:** Architecture v2 §2.8, §12, §11.1; DEVELOPMENT_PLAN S8

## Context
S8 is "staging + deploy-on-merge + SPIFFE mesh." The actual deploy needs a
Kubernetes cluster, which needs a cloud account we don't have yet. But the
deploy ARTIFACTS — chart, image build, workflow, mesh config — are buildable
and validatable now, so a cluster can be pointed at them the day it exists.

## Decision
1. **One Helm chart, two profiles** (`deploy/helm/truvo`). Templates iterate
   a `services` map; the Full Mesh (SaaS) and Compact (air-gap) profiles
   differ ONLY in `values-fullmesh.yaml` / `values-compact.yaml` (§2.8) —
   replica counts, data-store endpoints, SPIFFE on/off, resource sizes.
   Validated with `helm lint` + `helm template` for both profiles.
2. **Generic service image** (`deploy/docker/Dockerfile.service`,
   parameterized by `SERVICE`): every service builds identically, local
   `truvo-*` libs installed first (T6 dependency-confusion guard). One
   Dockerfile, ten images.
3. **Images to GHCR**, tagged with the release SHA + `latest`. cosign
   signing + CycloneDX SBOM attestation attach in the build step (the
   S0-exit DoD gate: no unsigned image is deployable) — wired as the next
   hardening pass.
4. **Deploy workflow is honest about the missing cluster**: `build-and-push`
   always runs; `deploy` is a clean no-op until a `STAGING_KUBECONFIG`
   secret exists. Manual/tag trigger, not every-merge, to keep CI cheap
   until there's a consumer.
5. **SPIFFE/SPIRE mesh** (§11.1): enabled per-profile (`global.spiffe`).
   Full Mesh runs each service under its own SPIFFE ID with mesh-enforced
   mTLS; Compact leaves it off (single rack) but keeps app-layer svcauth
   (S7) — the two are defense in depth (ADR-0005), so Compact loses one
   layer, not both.
6. **Migrations run as a pre-install/pre-upgrade Helm hook** before any
   service starts; the content-hash-locked runner makes re-runs safe.

## Consequences
The day a cloud account and cluster exist, staging is `helm upgrade --install`
away — no new authoring. Costs: the chart is unproven against a live cluster
(lint/template only) until then, and image build/push isn't exercised until
the workflow first runs. Revisit triggers: first real cluster (validate the
chart end to end, wire cosign/SBOM, turn on deploy), or a managed-Kubernetes
choice that changes ingress/secrets integration.

## Still blocked on the user (external)
Cloud account (cluster + registry consumer), then: set `STAGING_KUBECONFIG`,
run deploy, validate the chart live, and enable image signing.

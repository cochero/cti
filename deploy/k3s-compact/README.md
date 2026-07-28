# Compact (air-gap) reference deployment

k3s single-rack reference for the Compact profile (Architecture v2 §12).

- **Reference:** Architecture v2 §12; deploy/helm/truvo (values-compact.yaml); ADR-0010
- **Owner:** Platform
- **Status:** Helm chart validated (lint/template); live k3s bring-up pending a test rack

## Bring-up sketch (on the customer rack)
1. Install k3s (single or 3-node): `curl -sfL https://get.k3s.io | sh -`
2. Load the signed offline image bundle (Architecture §12): images arrive as
   a signed tarball, verified by the attestation tool, then
   `k3s ctr images import truvo-images.tar`.
3. In-rack data stores (Postgres+AGE+pgvector+TimescaleDB, Redpanda, MinIO,
   OpenBao backed by the customer HSM) via the Compact compose/manifests.
4. `helm upgrade --install truvo /path/to/chart -f values-compact.yaml`.

## What makes Compact air-gap-clean
- Every bundled component is permissively licensed (OpenSearch/Redpanda/AGE
  chosen for redistribution — ADR notes across the repo).
- No telemetry leaves the rack; updates arrive as signed offline bundles.
- App-layer service identity (svcauth, S7) holds even without the SPIFFE mesh.

## Not yet
- A live k3s bring-up on a real/simulated rack (chart is lint/template-validated).
- The signed offline bundle pipeline (weights + images + intel deltas + SBOM).

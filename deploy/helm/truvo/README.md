# TRUVO Helm chart

One chart, two deployment profiles (Architecture v2 §2.8, §12). The profiles
differ ONLY in values — never in templates.

## Validate (no cluster needed)
```bash
helm lint . -f values-fullmesh.yaml
helm lint . -f values-compact.yaml
helm template truvo . -f values-fullmesh.yaml   # renders SaaS manifests
helm template truvo . -f values-compact.yaml    # renders air-gap manifests
```

## Deploy (needs a cluster — S8, gated on a cloud account)
```bash
helm upgrade --install truvo . -f values-fullmesh.yaml   --set global.image.tag=<sha> --namespace truvo --create-namespace
```

## What differs between profiles
| | Full Mesh (SaaS) | Compact (air-gap) |
|---|---|---|
| replicas | HA (2 for hot-path services) | 1 across the board |
| SPIFFE mesh mTLS | on | off (app-layer svcauth still on) |
| data stores | managed/clustered (Kafka, Neo4j, Qdrant, OpenSearch) | in-rack single-binary (Redpanda, AGE+pgvector, vLLM) |
| resources | larger | minimal |

Everything else — the templates, the service set, the migration hook — is
identical. Adding a service is a `values.yaml` edit, not a template change.

Migrations run as a pre-install/pre-upgrade hook (content-hash-locked runner,
safe to re-run) before any service starts.

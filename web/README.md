# web (React) — the analyst console + CISO dashboard

TRUVO's face: the priority queue, score decomposition drill-down, rule
review/release, ATT&CK heatmap, and CISO posture dashboard — served
same-origin against the Django core's MIS API (Caddy routes `/api` to
core; the SPA never talks to raw microservices).

## Dev

```bash
npm install
npm run dev        # vite on :5173 (next free port if taken), proxies /api -> :8000
npm run build      # tsc + production bundle -> dist/
```

Requires the Django core running on :8000 (`core/manage.py runserver`).
Override with `TRUVO_CORE_URL`. Login with the demo users
(`python manage.py seed_demo`): demo-analyst@truvo.local / demo-pass.

## Views

| Route | What it shows |
|---|---|
| `/` | CISO dashboard: scored threats, KEV in top, coverage, identity exposure |
| `/priorities` | The PRIORITIZE queue: latest score per CVE, KEV/EPSS/PoC signals |
| `/priorities/:cve` | Full factor decomposition served from the ledger entry + related rules |
| `/rules` | HUNT output: staged Sigma content, release/reject (analyst+, ledger-recorded) |
| `/heatmap` | ATT&CK matrix lit by corroborated claim volume (last 90 days) |

## Production

`deploy/docker/Dockerfile.web` — multi-stage build (node -> nginx-alpine)
with SPA fallback routing and immutable asset caching. Caddy (see
`deploy/vps/Caddyfile`) serves it same-origin and routes `/api`, `/oidc`,
`/admin`, `/static` to the core.

## Data contract

All reads/writes go through the MIS API (`core/tenancy/mis.py`). Rule
release is the only write: RBAC-gated (analyst/admin), state-machine
enforced (staged -> active/rejected; nothing resurrects a rejected rule),
and every transition appends a hash-chained ledger entry.

Before first staging traffic this component needs: OTel web-vitals
instrumentation and a runbook in `ops/runbooks/` (see
`services/ledger/THREAT_MODEL.md` for the pattern).

# TRUVO Security Review — Senior Engineer Onboarding Assessment

> **REmediation status (2026-09-17):** FIXED in code and tested —
> C2 (LLM max_tokens/size/budget), C3 (DEBUG fails closed), H1
> (throttle + account lockout + password policy), H4-partial
> (webhook alerts + gate-rejection anomaly from the cycle; full
> metrics stack still open), H5 (retention purges, RLS-restricted,
> ledger-recorded), H6-partial (pip-audit/npm-audit CI + Dependabot;
> image pinning + signing still open), H3 (poisoning canaries,
> automated + live-run), M1 (ATT&CK existence filter), M8 (CSP),
> C1 (segmented backend/edge networks + llm-egress proxy in the prod
> compose; k8s NetworkPolicy still open). Still open: full
> observability stack, mTLS rollout to remaining services, MFA,
> supply-chain signing, M2-M7.

**Reviewer stance:** new senior security engineer, first full pass over the
platform. Lens: OWASP ASVS, OWASP Top 10 for LLM Applications, NIST CSF 2.0,
SLSA supply-chain, SOC 2 Trust Services Criteria, and the project's own
Architecture v2 (§3 threat model) — which is unusually good and honest.
Findings are evidence-backed (file:behavior), severities are my judgement.

**Verdict up front:** the security *architecture* is top-decile for the
category — threat-modeled, deterministic scoring, quarantine + gate on all
model output, hash-chained ledger, RLS tenancy, signed outbound actions.
The gaps are almost all *implementation debt against the platform's own
spec*, concentrated in: network enforcement of the LLM sandbox, authN
hardening, observability/alerting (zero today in prod compose), supply-chain
pinning, and the DPA-promised retention jobs. Nothing found invalidates the
design; several items would block a serious buyer's security review.

---

## What is genuinely solid (keep and defend)

| Control | Evidence |
|---|---|
| LLM output quarantine | LLMs propose; schema gate strips unauthorized fields, validates enums/bounds; corroboration + §7.3 action floor decide trust. Live-tested incl. embedded prompt injection (model extracted only the legitimate CVE; injection influenced nothing structural) |
| Deterministic, replayable scoring | 308/308 ledger entries re-derived bit-exact in the published calibration report; verifier refuses vendored engine copies |
| Tenant isolation | Postgres RLS forced on all tenant tables + automated leak tests in CI; onboarding writes under target-tenant context (tested) |
| Append-only audit ledger | Hash-chained, external anchoring (ADR-0004), tamper-evident on real storage |
| Action integrity | 3-tier policy matrix, hardcoded circuit breakers, signed single-use commands; gateway refuses unsigned/replayed |
| Structured feeds bypass model risk entirely | KEV/EPSS/NVD/ATT&CK parse deterministically — injection fields have no code path to ride |
| Secrets | OpenBao in prod mode, per-tenant vault partitions, bootstrap-generated secrets |
| Edge exposure | Only Caddy exposed; services/stores internal-network-only; security headers (HSTS, XCTO, XFO, Referrer-Policy) |

---

## Findings

### CRITICAL

**C1 — The no-egress LLM sandbox is designed, not enforced.**
Architecture §3.1-T2's mitigation says extraction runs "in a no-egress
sandbox; deployment enforces network isolation." No deployment does: the
extraction subprocess runs with full network access in every profile
(dev, VPS compose, Helm). A prompt-injection that recruits tool use, or a
compromised dependency in the extraction image, can exfiltrate everything
it processes (collected intel; in future, customer-context-enriched docs)
to any endpoint.
**Fix:** dedicated compose network / k8s NetworkPolicy for extraction with
default-deny egress and an explicit allow-list (object store + the LLM API
endpoint only). The LLM allow-list is deliberately *narrow*: DNS-pinned to
the configured provider. This is the single highest-value control gap.

**C2 — Unbounded LLM responses.** `llm_adapter.py` sends no `max_tokens`
and imposes no response-size cap; retry included. A hostile or
misbehaving provider (or a pathological document) can return arbitrarily
large completions → memory exhaustion/DoS of extraction, and runaway cost
on paid tiers.
**Fix:** `max_tokens` (e.g. 4096) in the request; hard byte cap on
`resp.content` before parsing; per-cycle token budget with abort+alert.

**C3 — `DEBUG` fails open.** `settings.py` defaults `TRUVO_DEBUG` unset →
DEBUG=1. A prod deployment that forgets the env var gets debug pages,
stack traces, and permissive cookie behavior.
**Fix:** default to `"0"`, require explicit opt-in for dev.

### HIGH

**H1 — Public login endpoint with zero brute-force protection.** No DRF
throttling classes configured, no account lockout, no per-IP limits, no
MFA. The code itself notes "rate limiting arrives with the gateway" — no
gateway exists yet. Also `AUTH_PASSWORD_VALIDATORS` is unset (no password
policy at all).
**Fix:** DRF throttle (per-IP + per-account) on auth views, exponential
lockout, validators on, and an alert on failure spikes. MFA (TOTP) for
admin/analyst roles before any design-partner data.

**H2 — Flat internal network; service auth only on 2 of ~10 services.**
`svcauth` request-signing is enforced by gateway + ledger only; scoring,
detection-factory, provenance, extraction, detect accept anything that
reaches them. The assumed compensating control — network isolation — is a
single shared bridge with no segmentation: any compromised container
reaches every service and every datastore. Architecture §11.1 demands
mTLS/SPIFFE everywhere.
**Fix (staged):** segment networks by trust zone (edge / pipeline /
data), then roll svcauth verification to remaining state-changing
services; mTLS as the follow-on.

**H3 — No poisoning canaries (§7.4).** The eval-harness contains no
canary mechanism; the quarterly red-team obligation hasn't started. The
§7.3 floor is enforced in code, but nothing *tests* that a determined
poison narrative can't cross it.
**Fix:** canary corpus + injection into staging collection replica in the
scheduled cycle; any canary crossing the action-eligibility floor → sev-1
alert. This is also a sales asset ("we attack ourselves quarterly").

**H4 — Zero observability and alerting in the production compose.** No
Prometheus/Grafana/Loki/OTel; `/healthz` only. `run_cycle` failures exit
non-zero "an alert, not a log line" — but nothing consumes the exit code
beyond container restart. The platform's own Definition of Done (§1.2:
dashboards + alerts before traffic) is unmet for the VPS profile.
**Fix:** minimal stack (Prometheus + Loki + Grafana + Alertmanager) in
the compose; `run_cycle` posts a webhook on failure; alert rules below.

**H5 — DPA-promised retention/purge jobs do not exist.** Onboarding
accepts a Data Governance policy promising hashed-credential purges on a
configured schedule and 13-month raw-artifact retention; no purge job is
implemented anywhere. A buyer's DPA audit would find the promise
unimplemented.
**Fix:** `ops/retention.py` in the cycle (artifact GC >13mo, credential
purge per tenant schedule), ledger-recorded purge events.

**H6 — Supply chain unpinned.** Datastores use `:latest` images; CI's
image signing/SBOM is a TODO comment; no pip-audit/npm-audit/Dependabot;
frontend lockfile committed (good) but not audited in CI. Architecture
§3.1-T6 demands SBOM + signed weights + reproducible builds.
**Fix:** digest-pinned images, pip-audit + npm audit in CI, cosign +
CycloneDX as the S0-exit TODO says, Dependabot on.

### MEDIUM

**M1 — ATT&CK technique IDs validated by format only.** The gate regex
accepts any `T\d{4}` — a poisoning narrative can seed valid-format fake
techniques into the heatmap. We already collect the real corpus; validate
IDs against it (cache the set at cycle start).

**M2 — LLM API key lives in an env file**, not OpenBao; no rotation
procedure. Move to vault; rotate the current key (it transited a chat).

**M3 — Tier-3 dual-control is single-human today.** The Flutter approvals
app is unimplemented; "two named humans" for critical actions is
architecture, not code. Interim: require two distinct analyst logins
before `activate` on Tier-3-class actions.

**M4 — No model-drift or abuse alerting.** §6.5's "drift alarms open
tickets automatically" is unimplemented. Alert on: gate-rejection-rate
spike (early signal of injection campaigns OR model drift), extraction
confidence-distribution shift, provider latency/error-rate anomaly,
token-spend anomaly.

**M5 — No Customer Zero.** The permanent synthetic tenant that must
survive every release before GA (§3.2) doesn't exist. Fold into the
canary + cycle work.

**M6 — Backup/restore drill manual; RPO/RTO unmeasured** (DoD §1.4).

**M7 — Collector egress/jurisdiction allow-lists (§11.3) not encoded** —
collection-legality policy is prose, not collector constraints.

**M8 — Onboarding one-time password delivered operator-to-customer out of
band**, no forced rotation at first login; CSP header absent from Caddy
(XFO/HSTS present) — add `Content-Security-Policy` for the SPA.

---

## LLM attack surface — explicit map (OWASP LLM Top 10)

| OWASP LLM | Status | Notes |
|---|---|---|
| LLM01 Prompt injection | **Strong, live-tested** | Gate + corroboration + floor; structured feeds bypass entirely. Residuals: M1 (fake-but-valid technique ids), H3 (no canaries), C1 (sandbox unenforced) |
| LLM02 Sensitive disclosure | **Good design, one gap** | Prompts contain doc text only — zero tenant context in extraction prompts (verified). Gap: hosted provider is a subprocessor; Compact profile keeps everything local; document + DPA coverage |
| LLM03 Supply chain | Partial | Hosted API = provider trust; air-gap weights signing designed not built; H6 applies to the pipeline image |
| LLM04 Data poisoning | **Floor enforced**; canaries missing (H3) | §7.3 in code in response-orchestrator |
| LLM06 Excessive agency | **Excellent** | Tiers, hardcoded breakers, signed single-use commands |
| (new) Model-output DoS / cost abuse | **Open** | C2 — max_tokens, size caps, budgets |
| (new) Provider account abuse | Open | Key in env (M2); no spend alerts (M4) |

## Alerting — what must exist before a design partner (none exists today)

1. **Auth:** failed-login rate per IP/account; lockout events; role changes
2. **Ledger:** chain-verification failure (sev-1 by SLO); anchoring gaps
3. **Pipeline/cycle:** stage failure (webhook from run_cycle), cycle
   duration anomaly, gate-rejection-rate spike, extraction-confidence
   drift, LLM token-spend & latency anomaly, provider error-rate
4. **Rules:** mass release/reject attempts (velocity per analyst),
   FP-budget breach demotions
5. **Platform:** egress traffic from the extraction zone to non-allow-list
   destinations (the C1 tripwire), container restart storms, vault seal
   events, backup failures

## Recommended order (first 30 days)

1. C3 + C2 (hours each) → 2. H1 auth hardening (1 day) → 3. C1 egress
isolation (2–3 days) → 4. H4 minimal observability + the alert list above
(1 week) → 5. H6 pinning + audits in CI (2 days) → 6. H3 canaries + M5
Customer Zero (fold into cycle) → 7. H5 retention jobs → 8. M8 CSP, M1
technique allow-list, M2 key into vault.

*This review is itself a living document — re-run it at each phase gate.*

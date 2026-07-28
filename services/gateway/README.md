# gateway-svc

The outbound push to customer SIEM/EDR — signed, replay-protected (Architecture v2 §8.3).

- **Reference:** Architecture v2 §8.3, §3.1-T4/T8; db/migrations/0013
- **Owner:** Product & Integrations
- **Status:** signed push + replay defense + vault creds live-tested; real SIEM adapters written, not verified

## The security model (§8.3)
Receives SIGNED commands from response-orchestrator and pushes approved actions. Enforced end to end: every command is Ed25519-signed (truvo_svcauth) — unsigned/tampered/stale is refused even from inside our network; a single-use nonce per tenant defeats replay even within the signature window; SIEM credentials are resolved from the vault per push, NEVER stored in our DB (T4: stolen DB access must not yield customer SIEM tokens). Only response-orchestrator's 'approved' verdicts should reach here.

## Proven (live)
- signed command pushes (vault creds resolved); unsigned/tampered/rogue-service refused (401); replayed nonce refused (409); command hash-chained to ledger + recorded; RLS isolates.

## Not yet verified
- SplunkAdapter / SentinelAdapter speak their HTTP APIs but are NOT tested against a live SIEM instance (no SIEM in dev). FakeAdapter drives tests. First real integration validates them.

Before staging: OTel, runbook, THREAT_MODEL.md.

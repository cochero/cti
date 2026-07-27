# detection-factory

Compile prioritized threats into tested, signed detection content (Architecture v2 §4.2 Hunt, §9.3).

- **Reference:** Architecture v2 §9.3, §3.1-T3; db/migrations/0011
- **Owner:** Product & Integrations + detection engineer
- **Status:** Sigma generation + FP-budget detonation + signing live-tested

## The flow
generate (deterministic Sigma) -> lint -> DETONATE against a benign corpus (+ malicious samples) -> sign (if passed) -> persist. A rule over its FP budget, or one that catches nothing, is stored 'rejected' and NEVER signed. Promotion to 'active' is a separate explicit step that re-verifies the signature (tamper check). Nothing auto-deploys.

## Security property (threat T3)
Malicious or sloppy detection content — a rule that over-matches benign traffic (would DoS a SIEM or whitelist an attacker) or catches nothing — is caught by the detonation FP-budget gate and rejected before it can be signed or shipped. Live tests prove an over-matching rule is rejected+unsigned+unpromotable, and a tampered rule is refused promotion.

## Not yet
- Transpile Sigma -> KQL/SPL/YARA-L (sigma backends) for target SIEMs.
- Detonation against a large real benign capture (v0 uses a representative corpus; mechanism is identical).
- Ed25519 rule signing (v0 uses per-tenant HMAC, same vault-key pattern as anchors).

Before staging: OTel, runbook, THREAT_MODEL.md.

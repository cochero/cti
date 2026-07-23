# extraction-svc

The stochastic zone: raw text -> CANDIDATE claims -> schema gate -> claims (Architecture v2 §6.1-6.2).

- **Reference:** Architecture v2 §3.1-T2, §6.1-6.2; contracts/events/intel.claim.v1.avsc
- **Owner:** Intelligence Pipeline
- **Status:** pipeline live-tested via FakeExtractor; LLM adapter written, not model-verified

## The security model (this is the point of the service)
"LLMs propose; the gate disposes." Nothing an extractor emits becomes a claim until `gate.py` validates structure, enums, formats, value bounds, and strips unauthorized fields. Even a successful prompt injection cannot set confidence or eligibility — the gate stops malformed output, and provenance's §7.3 floor strips authority. **The prompt-injection regression suite (tests/test_injection.py) is CI-enforced and only grows; a string that slips through blocks release.**

## What's proven (live/CI)
- Schema gate: injection containment + gate integrity (adversarial candidates all rejected).
- Full pipeline collect -> extract -> corroborate, injection defense across process boundaries (tests_e2e/).

## What's NOT yet verified
- `LLMExtractor` is written against the structured-decoding contract but needs a served model (hosted frontier API in SaaS; local vLLM in Compact). FakeExtractor drives all current tests.
- DLQ wiring for bad rawdocs mirrors provenance (S5) and lands with the HTTP service.

Before staging: OTel, runbook, THREAT_MODEL.md.

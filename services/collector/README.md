# collector-svc

Acquisition + content-addressed storage + rawdoc emission (Architecture v2 §4 Collection Layer).

- **Reference:** Architecture v2 §4, §5.2; contracts/events/intel.rawdoc.v1.avsc
- **Owner:** Intelligence Pipeline
- **Status:** walking skeleton — NVD collector written, FakeCollector live-tested via e2e

## What's proven
- Content-addressed artifact storage (truvo_objstore): idempotent, self-verifying.
- rawdoc emission onto the backbone; raw bytes never in the event, only the verifiable pointer.
- End-to-end through extraction + provenance (tests_e2e/).

## What's NOT yet verified
- `NVDCollector` speaks the real NVD 2.0 API but is not live-tested against NVD (network + rate limits). First run against NVD validates it.
- Scrapers of untrusted HTML / dark-web forums are deliberately NOT here yet — they MUST run in the no-egress sandbox (threat T2) and land in a later sprint.

Before staging: OTel, runbook, THREAT_MODEL.md (pattern: services/ledger/THREAT_MODEL.md).

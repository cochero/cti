-- 0005: provenance — source registry + claim ledger (Architecture v2 SS7).
--
-- These hold GLOBAL intelligence infrastructure (OSINT-derived, shared
-- across tenants), not tenant-scoped customer data — so no RLS here.
-- Claims are append-only: history of what sources asserted is evidence
-- and never mutates (same discipline as ledger_entries).

CREATE TABLE IF NOT EXISTS sources (
    source_id   text PRIMARY KEY CHECK (source_id ~ '^src-[a-z0-9][a-z0-9-]{1,62}$'),
    name        text NOT NULL,
    -- source class drives the action-eligibility floor (SS7.3)
    source_type text NOT NULL CHECK (source_type IN
        ('osint', 'dark_web', 'social', 'vendor_advisory', 'cert', 'first_party')),
    -- Admiralty-style reliability grade
    grade       char(1) NOT NULL DEFAULT 'F' CHECK (grade IN ('A','B','C','D','E','F')),
    url         text,
    active      boolean NOT NULL DEFAULT true,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS claims (
    claim_id                     uuid PRIMARY KEY,
    source_id                    text NOT NULL REFERENCES sources (source_id),
    provenance_id                uuid NOT NULL,
    observed_at_iso              text NOT NULL,
    raw_artifact_hash            char(64) NOT NULL,
    extraction_model_version     text NOT NULL,
    extraction_confidence_millis int  NOT NULL
        CHECK (extraction_confidence_millis BETWEEN 0 AND 1000),
    subject_type                 text NOT NULL CHECK (subject_type IN
        ('THREAT_ACTOR','MALWARE','CVE','INFRASTRUCTURE','CAMPAIGN','TTP')),
    subject_value                text NOT NULL,
    assertion                    text NOT NULL,
    object_value                 text,
    attack_technique_ids         text[] NOT NULL DEFAULT '{}',
    ingested_at                  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS claims_subject_idx
    ON claims (subject_type, subject_value);
CREATE INDEX IF NOT EXISTS claims_source_idx ON claims (source_id);

-- 0004 default privileges auto-granted full DML to truvo_app for
-- admin-created tables; claims are append-only evidence -> revoke.
REVOKE UPDATE, DELETE ON claims FROM truvo_app;

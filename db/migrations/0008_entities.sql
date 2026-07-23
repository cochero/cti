-- 0008: entity resolution — canonical entities + alias index (Arch §4.2).
--
-- The Lazarus = HIDDEN COBRA = APT38 = Diamond Sleet problem. Global intel
-- infrastructure (not tenant-scoped): every claim's subject resolves to a
-- canonical entity so downstream scoring reasons about one actor, not four
-- names. Aliases are curated data (intel-team + adjudication), never code.
--
-- Design: an alias row maps (normalized_value, entity_type) -> canonical.
-- Resolution is deterministic exact-match on the normalized form; fuzzy /
-- embedding-similarity clustering is a later enhancement (needs the vector
-- store) and always lands in the adjudication queue, never auto-merges.

CREATE TABLE IF NOT EXISTS entities (
    canonical_id   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_type    text NOT NULL CHECK (entity_type IN
        ('THREAT_ACTOR','MALWARE','CVE','INFRASTRUCTURE','CAMPAIGN','TTP')),
    canonical_name text NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS entity_aliases (
    entity_type      text NOT NULL,
    normalized_value text NOT NULL,   -- lowercased, whitespace-collapsed
    display_value    text NOT NULL,   -- as originally seen
    canonical_id     uuid NOT NULL REFERENCES entities (canonical_id) ON DELETE CASCADE,
    source           text NOT NULL DEFAULT 'seed',  -- seed | adjudicated | auto
    confidence_millis int NOT NULL DEFAULT 1000
        CHECK (confidence_millis BETWEEN 0 AND 1000),
    created_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (entity_type, normalized_value)
);

CREATE INDEX IF NOT EXISTS entity_aliases_canonical_idx
    ON entity_aliases (canonical_id);

-- Low-confidence / ambiguous merges land here for a human, never auto-applied.
CREATE TABLE IF NOT EXISTS resolution_adjudications (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_type    text NOT NULL,
    value_a        text NOT NULL,
    value_b        text NOT NULL,
    reason         text NOT NULL,
    similarity_millis int,
    status         text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','merged','rejected')),
    created_at     timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE ON entities TO truvo_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON entity_aliases TO truvo_app;
GRANT SELECT, INSERT, UPDATE ON resolution_adjudications TO truvo_app;
-- entities/adjudications are corrective, not append-only evidence, so
-- UPDATE is allowed; DELETE stays reserved to admin maintenance.

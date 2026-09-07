"""exploit_intel enrichment — derive the scoring read model from claims.

ADR-0007 made exploit_intel the scoring read model (epss/kev/cvss/poc per
CVE). This job derives it from the claims table — i.e. from data that has
already crossed the full pipeline (collector -> schema-gated extraction ->
provenance recording) — rather than from a side-channel fetch. One code
path produced the belief; this projects it. Re-running is idempotent.

    python -m app.enrich          # requires TRUVO_SCORING_DB_URL

The structured-feed assertions (extraction's StructuredFeedExtractor)
carry the values in object_value:
    structured:kev_listed  -> date listed (presence => kev = true)
    structured:epss_score  -> "0.97052"  (0..1 float as string)
    structured:cvss_score  -> "9.8"      (0..10 float as string)
Millis conversions: epss * 1000, cvss * 100. Values round half-up, and
object_value came from repr(float(...)) so the string round-trips exactly.
"""

import json
import os
from typing import Any, Dict

import psycopg2

# DISTINCT ON keeps the LATEST claim per CVE; corroboration and source
# grading live in provenance — this projection only carries values.
_KEV_SQL = """
INSERT INTO exploit_intel (cve, kev)
SELECT DISTINCT ON (subject_value)
       subject_value, true
  FROM claims
 WHERE assertion = 'structured:kev_listed' AND subject_type = 'CVE'
 ORDER BY subject_value, ingested_at DESC
ON CONFLICT (cve) DO UPDATE SET kev = true, updated_at = now()
"""

_EPSS_SQL = """
INSERT INTO exploit_intel (cve, epss_millis)
SELECT DISTINCT ON (subject_value)
       subject_value,
       greatest(0, least(1000, round(
           cast(object_value AS numeric) * 1000)))
  FROM claims
 WHERE assertion = 'structured:epss_score' AND subject_type = 'CVE'
   AND object_value IS NOT NULL
 ORDER BY subject_value, ingested_at DESC
ON CONFLICT (cve) DO UPDATE
  SET epss_millis = EXCLUDED.epss_millis, updated_at = now()
"""

_CVSS_SQL = """
INSERT INTO exploit_intel (cve, cvss_millis)
SELECT DISTINCT ON (subject_value)
       subject_value,
       greatest(0, least(1000, round(
           cast(object_value AS numeric) * 100)))
  FROM claims
 WHERE assertion = 'structured:cvss_score' AND subject_type = 'CVE'
   AND object_value IS NOT NULL
 ORDER BY subject_value, ingested_at DESC
ON CONFLICT (cve) DO UPDATE
  SET cvss_millis = EXCLUDED.cvss_millis, updated_at = now()
"""

# report-only: claim values outside their valid domain (epss 0..1, cvss
# 0..10) — i.e. rows the projection had to CLAMP. A claim stream feeding
# garbage should be visible, not clamped silent.
_AUDIT_SQL = """
SELECT count(*) FROM claims
 WHERE assertion IN ('structured:epss_score', 'structured:cvss_score')
   AND subject_type = 'CVE' AND object_value IS NOT NULL
   AND (cast(object_value AS numeric)
        * CASE WHEN assertion = 'structured:epss_score' THEN 1000 ELSE 100 END)
       NOT BETWEEN 0 AND 1000
"""


def run(cur) -> Dict[str, Any]:
    """Execute the projection. cur is a DBAPI cursor on a transaction."""
    counts = {}
    cur.execute(_KEV_SQL)
    counts["kev"] = cur.rowcount
    cur.execute(_EPSS_SQL)
    counts["epss"] = cur.rowcount
    cur.execute(_CVSS_SQL)
    counts["cvss"] = cur.rowcount
    cur.execute(_AUDIT_SQL)
    counts["clamped_or_bad"] = cur.fetchone()[0]
    cur.execute("SELECT count(*) FROM exploit_intel")
    counts["exploit_intel_rows"] = cur.fetchone()[0]
    return counts


def main() -> None:
    dsn = os.environ.get("TRUVO_SCORING_DB_URL")
    if not dsn:
        raise SystemExit("TRUVO_SCORING_DB_URL is required")
    conn = psycopg2.connect(dsn)
    try:
        with conn.cursor() as cur:
            counts = run(cur)
        conn.commit()
        print(json.dumps(counts))
    finally:
        conn.close()


if __name__ == "__main__":
    main()

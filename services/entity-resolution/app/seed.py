"""Seed the alias table from the curated file (idempotent).

    python -m app.seed

Re-running only adds missing aliases; existing canonical entities and
adjudicated merges are preserved.
"""

import json
import os
from pathlib import Path

from app.logic import normalize

SEED = Path(__file__).parent / "seed_aliases.json"


def seed(dsn=None) -> dict:
    import psycopg2

    conn = psycopg2.connect(dsn or os.environ["TRUVO_ENTITY_DB_URL"])
    conn.autocommit = False
    data = json.loads(SEED.read_text(encoding="utf-8"))
    entities = aliases = 0
    try:
        with conn.cursor() as cur:
            for entity_type, groups in data.items():
                if entity_type.startswith("_"):
                    continue
                for group in groups:
                    canonical = group["canonical"]
                    norm = normalize(canonical)
                    # canonical entity via its own normalized name
                    cur.execute(
                        "SELECT canonical_id FROM entity_aliases"
                        " WHERE entity_type = %s AND normalized_value = %s",
                        (entity_type, norm),
                    )
                    row = cur.fetchone()
                    if row:
                        cid = row[0]
                    else:
                        cur.execute(
                            "INSERT INTO entities (entity_type, canonical_name)"
                            " VALUES (%s, %s) RETURNING canonical_id",
                            (entity_type, canonical),
                        )
                        cid = cur.fetchone()[0]
                        entities += 1
                        cur.execute(
                            "INSERT INTO entity_aliases (entity_type,"
                            " normalized_value, display_value, canonical_id, source)"
                            " VALUES (%s, %s, %s, %s, 'seed')"
                            " ON CONFLICT DO NOTHING",
                            (entity_type, norm, canonical, cid),
                        )
                    for alias in group["aliases"]:
                        cur.execute(
                            "INSERT INTO entity_aliases (entity_type,"
                            " normalized_value, display_value, canonical_id, source)"
                            " VALUES (%s, %s, %s, %s, 'seed')"
                            " ON CONFLICT (entity_type, normalized_value)"
                            " DO NOTHING",
                            (entity_type, normalize(alias), alias, cid),
                        )
                        if cur.rowcount:
                            aliases += 1
        conn.commit()
    finally:
        conn.close()
    return {"entities_created": entities, "aliases_added": aliases}


if __name__ == "__main__":
    print(json.dumps(seed()))

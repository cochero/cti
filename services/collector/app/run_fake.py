"""Fake-collection entrypoint for e2e tests.

Reads newline-delimited documents from TRUVO_FAKE_DOCS (JSON list of
{"content": str, "content_type": str}) and runs them through the real
CollectorRunner. Used by tests_e2e to feed the pipeline deterministically.

    python -m app.run_fake
"""

import json
import os

from app.collectors import CollectedDoc, FakeCollector
from app.main import CollectorRunner


def main() -> None:
    docs_json = os.environ.get("TRUVO_FAKE_DOCS", "[]")
    raw = json.loads(docs_json)
    docs = [
        CollectedDoc(
            content=d["content"].encode(),
            content_type=d.get("content_type", "text/plain"),
            origin_url=d.get("origin_url"),
        )
        for d in raw
    ]
    collector = FakeCollector(
        docs,
        source_id=os.environ.get("TRUVO_FAKE_SOURCE_ID", "src-fake"),
        trust_class=os.environ.get("TRUVO_FAKE_TRUST_CLASS", "OSINT"),
    )
    result = CollectorRunner(bucket=os.environ.get("TRUVO_RAW_BUCKET", "truvo-raw")).run(
        collector
    )
    print(json.dumps(result))


if __name__ == "__main__":
    main()

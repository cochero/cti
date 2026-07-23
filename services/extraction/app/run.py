"""Extraction batch entrypoint.

Consumes intel.rawdoc.v1, extracts with the configured extractor
(FakeExtractor by default; TRUVO_EXTRACTOR selects), gates, emits claims.

    python -m app.run
"""

import json
import os

from app.extractors import FakeExtractor
from app.main import ExtractionPipeline


def _extractor():
    which = os.environ.get("TRUVO_EXTRACTOR", "fake")
    if which == "fake":
        return FakeExtractor()
    raise SystemExit("unknown TRUVO_EXTRACTOR=%r (llm needs a served model)" % which)


def main() -> None:
    pipeline = ExtractionPipeline(_extractor())
    result = pipeline.consume_batch(
        max_messages=int(os.environ.get("TRUVO_BATCH_MAX", "500")),
        timeout_s=float(os.environ.get("TRUVO_BATCH_TIMEOUT", "12")),
        group=os.environ.get("TRUVO_GROUP"),
    )
    print(json.dumps(result))


if __name__ == "__main__":
    main()

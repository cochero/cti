"""Extraction batch entrypoint.

Consumes intel.rawdoc.v1, extracts, gates, emits claims. The base
extractor (TRUVO_EXTRACTOR: fake | llm) is wrapped in
StructuredFeedExtractor: authoritative feed JSON parses directly, all
other content keeps the quarantined text path — including the LLM path:
the served model sees untrusted text as delimited DATA and its output is
still just candidates at the gate.

    TRUVO_EXTRACTOR=llm python -m app.run   # needs TRUVO_LLM_* env
    python -m app.run                       # deterministic fake
"""

import json
import os

from app.extractors import FakeExtractor, LLMExtractor, StructuredFeedExtractor
from app.llm_adapter import adapter_from_env
from app.main import ExtractionPipeline


def _extractor():
    which = os.environ.get("TRUVO_EXTRACTOR", "fake")
    if which == "fake":
        return StructuredFeedExtractor(FakeExtractor())
    if which == "llm":
        model = os.environ.get("TRUVO_LLM_MODEL", "served-model")
        return StructuredFeedExtractor(
            LLMExtractor(adapter_from_env(),
                         model_version="llm-%s" % model))
    raise SystemExit("unknown TRUVO_EXTRACTOR=%r" % which)


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

"""Load the REAL scoring engine for replay verification.

Eval-harness deliberately does not vendor a copy of the engine: verifying
against a copy would prove nothing about the engine that produced the
scores. This loader imports scoring's engine.py directly from the repo
checkout (or a deployed path via TRUVO_ENGINE_PATH) under a distinct
module name, avoiding the `app` package collision between services.

engine.py is pure (dataclasses + functions, no intra-service imports),
so standalone loading is sound. If it ever grows dependencies, this
loader fails loudly and the report says so — never silently degrades.
"""

import importlib.util
import os
from pathlib import Path

__all__ = ["ScoringInput", "score", "weights_for_version"]


def _candidate_paths():
    env_path = os.environ.get("TRUVO_ENGINE_PATH")
    if env_path:
        yield Path(env_path)
    # repo layout: services/eval-harness/app/ -> services/scoring/app/
    yield (Path(__file__).resolve().parents[2] / "scoring" / "app"
           / "engine.py")


def _load_engine():
    for path in _candidate_paths():
        if path.is_file():
            spec = importlib.util.spec_from_file_location(
                "truvo_scoring_engine_real", path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
    raise RuntimeError(
        "scoring engine not found — set TRUVO_ENGINE_PATH to the deployed "
        "services/scoring/app/engine.py (replay verification refuses to "
        "run against anything but the real engine)")


_engine = _load_engine()
ScoringInput = _engine.ScoringInput
score = _engine.score

_WEIGHTS = {"weights-v0": _engine.WEIGHTS_V0}


def weights_for_version(version: str):
    return _WEIGHTS.get(version)

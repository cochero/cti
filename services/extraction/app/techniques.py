r"""Known ATT&CK technique ids — the existence check the gate can't do.

The schema gate validates FORMAT (T\d{4}(.\d{3})?) because it must stay
pure and model-independent. But a poisoning narrative can mint valid-
format fake techniques (T9999) and pollute the heatmap. This module loads
the real corpus (bundled, regenerated from the live STIX bundle) and the
extractor drops unknown ids — format-valid fabrications included.

The gate remains the authority on structure; this is the authority on
existence. Both must pass.
"""

import json
import os
from pathlib import Path

__all__ = ["KNOWN_TECHNIQUES", "filter_known_techniques"]

_BUNDLED = (Path(__file__).resolve().parent / "data"
            / "attack_techniques.json")


def _load() -> frozenset:
    # operators can override/extend (e.g. pre-release ATT&CK) via env path
    src = Path(os.environ.get("TRUVO_TECHNIQUES_FILE") or _BUNDLED)
    try:
        payload = json.loads(src.read_text(encoding="utf-8"))
        return frozenset(payload["techniques"])
    except (OSError, ValueError, KeyError):
        # unparseable/missing corpus: EMPTY set = every technique id is
        # dropped (fail closed — heatmap loses data, never gains fabrications)
        return frozenset()


KNOWN_TECHNIQUES = _load()


def filter_known_techniques(ids):
    """Split into (known, dropped). Unknown-but-valid-format ids are
    counted so the pipeline can alert on a fabrication pattern."""
    known, dropped = [], []
    for tid in ids or []:
        (known if tid in KNOWN_TECHNIQUES else dropped).append(tid)
    return known, dropped

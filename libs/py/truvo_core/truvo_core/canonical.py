"""Canonical JSON serialization.

Every hash in the platform (ledger entries, replay checks, artifact
content-addressing) is computed over these bytes. If two processes ever
serialize the same logical object to different bytes, the replay property
breaks -- so this module is deliberately strict:

- keys sorted, no whitespace, UTF-8, no ASCII escaping
- only JSON-safe types: dict, list, str, int, bool, None
- floats are REJECTED: cross-platform float formatting is not guaranteed
  to be byte-stable. Store decimals as strings or scaled integers
  (e.g. score_millis = 87421, never score = 87.421).
- NaN/Infinity rejected implicitly (allow_nan=False) and by the float rule.
"""

import json
from typing import Any

__all__ = ["canonical_json", "CanonicalizationError"]


class CanonicalizationError(TypeError):
    """Raised when an object cannot be canonically serialized."""


def _reject_unsafe(obj: Any, path: str = "$") -> None:
    if obj is None or isinstance(obj, (str, bool)):
        return
    # bool is a subclass of int; checked above so plain ints pass here.
    if isinstance(obj, int):
        return
    if isinstance(obj, float):
        raise CanonicalizationError(
            "float at %s: floats are not byte-stable across platforms; "
            "use a string decimal or a scaled integer" % path
        )
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise CanonicalizationError(
                    "non-string key %r at %s: canonical JSON requires string keys"
                    % (k, path)
                )
            _reject_unsafe(v, "%s.%s" % (path, k))
        return
    if isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            _reject_unsafe(v, "%s[%d]" % (path, i))
        return
    raise CanonicalizationError(
        "unsupported type %s at %s" % (type(obj).__name__, path)
    )


def canonical_json(obj: Any) -> bytes:
    """Serialize *obj* to canonical JSON bytes.

    Deterministic: equal logical objects always produce identical bytes,
    on any platform, in any process.
    """
    _reject_unsafe(obj)
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")

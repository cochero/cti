import pytest
from truvo_core.canonical import CanonicalizationError, canonical_json


def test_deterministic_key_order():
    a = canonical_json({"b": 1, "a": 2})
    b = canonical_json({"a": 2, "b": 1})
    assert a == b == b'{"a":2,"b":1}'


def test_nested_and_unicode():
    obj = {"z": [1, {"y": "über"}], "a": None, "ok": True}
    out = canonical_json(obj)
    # non-ASCII stays raw UTF-8, no escaping
    assert "über".encode("utf-8") in out
    assert out == canonical_json(dict(reversed(list(obj.items()))))


def test_floats_rejected():
    with pytest.raises(CanonicalizationError):
        canonical_json({"score": 87.421})


def test_non_string_keys_rejected():
    with pytest.raises(CanonicalizationError):
        canonical_json({1: "x"})


def test_unsupported_types_rejected():
    with pytest.raises(CanonicalizationError):
        canonical_json({"when": object()})

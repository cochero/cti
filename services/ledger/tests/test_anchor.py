import pytest
from app.anchor import (
    AnchorMismatch,
    AnchorRecord,
    check_chain_extends,
    make_anchor,
    verify_anchor_signature,
)
from truvo_core.hashchain import append_entry


def build_chain(n=3):
    entries, prev = [], None
    for i in range(n):
        prev = append_entry(
            prev, ts_iso="2026-07-23T00:00:%02dZ" % i, tenant="t", actor="svc",
            kind="k", payload={"i": i},
        )
        entries.append(prev)
    return entries


def test_anchor_signature_roundtrip():
    a = make_anchor("t", "2026-07-23T00:00:00Z", 2, "a" * 64)
    assert verify_anchor_signature(a)


def test_forged_signature_rejected():
    a = make_anchor("t", "2026-07-23T00:00:00Z", 2, "a" * 64)
    forged = AnchorRecord(**{**a.__dict__, "signature": "0" * 64})
    assert not verify_anchor_signature(forged)
    with pytest.raises(AnchorMismatch, match="signature"):
        check_chain_extends(build_chain(), forged)


def test_chain_extending_anchor_passes():
    chain = build_chain(5)
    a = make_anchor("t", "2026-07-23T00:00:00Z", 2, chain[2].entry_hash)
    check_chain_extends(chain, a)  # no raise


def test_rewritten_history_detected():
    chain = build_chain(5)
    a = make_anchor("t", "2026-07-23T00:00:00Z", 2, chain[2].entry_hash)
    rewritten = build_chain(5)[:2] + [
        append_entry(
            build_chain(2)[-1], ts_iso="2026-07-23T09:00:00Z", tenant="t",
            actor="attacker", kind="k", payload={"i": "forged"},
        )
    ]
    with pytest.raises(AnchorMismatch, match="rewritten"):
        check_chain_extends(rewritten, a)


def test_truncated_chain_detected():
    chain = build_chain(5)
    a = make_anchor("t", "2026-07-23T00:00:00Z", 4, chain[4].entry_hash)
    with pytest.raises(AnchorMismatch, match="missing"):
        check_chain_extends(chain[:3], a)

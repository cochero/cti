"""Ledger core tests.

These are the CI embodiment of two architecture guarantees:
- tamper-evidence (Architecture v2 SS3.1-T7)
- the replay property: rebuilding from content reproduces stored hashes
  bit-for-bit (Architecture v2 SS2.4, SS9.4)
"""

import dataclasses

import pytest
from truvo_core.hashchain import (
    GENESIS_HASH,
    ChainError,
    append_entry,
    replay_hashes,
    verify_chain,
)


def build_chain(n=5):
    entries = []
    prev = None
    for i in range(n):
        prev = append_entry(
            prev,
            ts_iso="2026-07-22T00:00:%02dZ" % i,
            tenant="tenant-a",
            actor="scoring-svc",
            kind="score.emitted",
            payload={"threat": "TA-%d" % i, "score_millis": 80000 + i},
        )
        entries.append(prev)
    return entries


def test_genesis_links_to_zero_hash():
    (genesis,) = build_chain(1)
    assert genesis.seq == 0
    assert genesis.prev_hash == GENESIS_HASH
    assert genesis.entry_hash == genesis.compute_hash()


def test_verify_valid_chain():
    entries = build_chain(5)
    assert verify_chain(entries) == 5


def test_payload_tamper_detected():
    entries = build_chain(5)
    tampered = dataclasses.replace(
        entries[2], payload={"threat": "TA-2", "score_millis": 99999}
    )
    with pytest.raises(ChainError, match="seq 2"):
        verify_chain(entries[:2] + [tampered] + entries[3:])


def test_reordering_detected():
    entries = build_chain(5)
    with pytest.raises(ChainError):
        verify_chain([entries[0], entries[2], entries[1], entries[3], entries[4]])


def test_deletion_detected():
    entries = build_chain(5)
    with pytest.raises(ChainError):
        verify_chain(entries[:2] + entries[3:])


def test_replay_reproduces_hashes_bit_for_bit():
    """THE replay property. If this test ever fails, it is a sev-1."""
    entries = build_chain(20)
    assert replay_hashes(entries) == [e.entry_hash for e in entries]


def test_replay_diverges_if_content_differs():
    entries = build_chain(3)
    altered = dataclasses.replace(
        entries[1], payload={"threat": "TA-1", "score_millis": 1}
    )
    rebuilt = replay_hashes([entries[0], altered, entries[2]])
    assert rebuilt[0] == entries[0].entry_hash
    assert rebuilt[1] != entries[1].entry_hash  # divergence is visible...
    assert rebuilt[2] != entries[2].entry_hash  # ...and cascades forward

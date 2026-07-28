"""IOC matching — bloom pre-screen then exact (Architecture v2 §4.2 Detect).

At stream scale, checking every inbound IOC against a tenant watchlist with
an exact lookup is expensive. A bloom filter pre-screens: it can say
"definitely not in the set" cheaply (no false negatives), and only the
"maybe" cases pay for an exact check. This module is the pure core; the
service feeds it the watchlist and the inbound batch.

Bloom guarantee, and why it is safe here: NO FALSE NEGATIVES. A real IOC
match is never missed by the pre-screen; false positives only cost an
exact re-check, never a missed detection.
"""

import hashlib
from typing import Iterable, List, Set, Tuple

__all__ = ["BloomFilter", "match_iocs"]


class BloomFilter:
    def __init__(self, expected: int, k: int = 4):
        # size the bit array ~10 bits/element (low FP rate), min 64 bits
        self.size = max(64, expected * 10)
        self.k = k
        self.bits = 0

    def _positions(self, value: str) -> List[int]:
        out = []
        for i in range(self.k):
            h = hashlib.sha256(("%d:%s" % (i, value)).encode()).digest()
            out.append(int.from_bytes(h[:8], "big") % self.size)
        return out

    def add(self, value: str) -> None:
        for p in self._positions(value):
            self.bits |= (1 << p)

    def __contains__(self, value: str) -> bool:
        return all((self.bits >> p) & 1 for p in self._positions(value))


def match_iocs(watchlist: Set[str],
               inbound: Iterable[str]) -> Tuple[List[str], int]:
    """Return (matched_values, prescreen_rejections). Builds a bloom over the
    watchlist, pre-screens the inbound stream, and exact-checks survivors.

    Correctness: every returned value is genuinely in the watchlist (exact
    check), and no watchlist member in `inbound` is ever missed (bloom has
    no false negatives)."""
    bloom = BloomFilter(expected=max(1, len(watchlist)))
    for w in watchlist:
        bloom.add(w)
    matched = []
    rejected = 0
    for value in inbound:
        if value not in bloom:      # definitely not in the set
            rejected += 1
            continue
        if value in watchlist:      # exact confirm (weed out bloom FPs)
            matched.append(value)
    return matched, rejected

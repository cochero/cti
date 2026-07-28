"""Pure IOC + credential-leak units — the §11.3 privacy guarantees.

The credential-leak tests encode the binding rules: only registered-domain
credentials are surfaced (we don't warehouse the internet's PII), and
cleartext is never present in the output (only salted hashes).
"""

from app.credleak import salt_credential, scan_breach
from app.ioc import BloomFilter, match_iocs

# --- IOC matching -----------------------------------------------------------

def test_bloom_has_no_false_negatives():
    """The safety-critical bloom property: a member is never reported absent."""
    values = ["ioc-%d.example.com" % i for i in range(500)]
    b = BloomFilter(expected=len(values))
    for v in values:
        b.add(v)
    for v in values:
        assert v in b, "bloom false negative on %s — a real IOC would be missed" % v


def test_match_finds_watchlist_hits_only():
    watchlist = {"1.2.3.4", "evil.com", "deadbeef"}
    inbound = ["1.2.3.4", "9.9.9.9", "evil.com", "clean.org"]
    matched, rejected = match_iocs(watchlist, inbound)
    assert set(matched) == {"1.2.3.4", "evil.com"}
    assert rejected >= 1  # at least the clearly-absent ones pre-screened out


def test_match_no_watchlist_matches_nothing():
    matched, rejected = match_iocs(set(), ["a", "b", "c"])
    assert matched == []
    assert rejected == 3


def test_bloom_prescreen_rejects_absent():
    watchlist = {"a.com"}
    _matched, rejected = match_iocs(watchlist, ["z.com"] * 10)
    assert rejected == 10  # none survive pre-screen (no exact checks wasted)


# --- credential-leak (§11.3) ------------------------------------------------

def test_only_registered_domains_surface():
    records = [
        {"email": "ceo@acme.com", "credential": "hunter2"},
        {"email": "bob@notacustomer.com", "credential": "pw"},
        {"email": "dev@acme.com", "credential": "pw2"},
    ]
    hits = scan_breach(records, {"acme.com"}, salt="s")
    domains = {h["domain"] for h in hits}
    assert domains == {"acme.com"}
    assert len(hits) == 2  # notacustomer.com dropped entirely, never stored


def test_cleartext_never_in_output():
    records = [{"email": "x@acme.com", "credential": "SUPERSECRET"}]
    hits = scan_breach(records, {"acme.com"}, salt="s")
    blob = repr(hits)
    assert "SUPERSECRET" not in blob
    assert "cred_salted_sha256" in hits[0]
    assert "credential" not in hits[0]


def test_salt_changes_hash():
    a = salt_credential("pw", "salt-a")
    b = salt_credential("pw", "salt-b")
    assert a != b
    assert a == salt_credential("pw", "salt-a")  # deterministic per salt


def test_domain_match_is_case_insensitive():
    hits = scan_breach([{"email": "A@ACME.com", "credential": "p"}],
                       {"acme.com"}, salt="s")
    assert len(hits) == 1
    assert hits[0]["local_part"] == "a"
    assert hits[0]["domain"] == "acme.com"


def test_malformed_email_ignored():
    hits = scan_breach([{"email": "not-an-email", "credential": "p"},
                        {"email": "", "credential": "p"}],
                       {"acme.com"}, salt="s")
    assert hits == []

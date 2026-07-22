import pytest

from truvo_svcauth import (
    MAX_SKEW_S,
    SvcAuthError,
    generate_keypair,
    sign_headers,
    verify_headers,
)

PRIV, PUB = generate_keypair()
KEYS = {"scoring-svc": PUB}


def get_pubkey(svc):
    return KEYS[svc]


def _signed(body=b'{"x":1}', path="/v1/entries", method="POST", now=1000000.0):
    return sign_headers("scoring-svc", PRIV, method, path, body, now=now)


def test_roundtrip():
    h = _signed()
    svc = verify_headers(h, "POST", "/v1/entries", b'{"x":1}', get_pubkey,
                         now=1000000.0)
    assert svc == "scoring-svc"


def test_tampered_body_rejected():
    h = _signed()
    with pytest.raises(SvcAuthError, match="verification failed"):
        verify_headers(h, "POST", "/v1/entries", b'{"x":2}', get_pubkey,
                       now=1000000.0)


def test_replayed_to_other_path_rejected():
    h = _signed()
    with pytest.raises(SvcAuthError, match="verification failed"):
        verify_headers(h, "POST", "/v1/other", b'{"x":1}', get_pubkey,
                       now=1000000.0)


def test_stale_timestamp_rejected():
    h = _signed(now=1000000.0)
    with pytest.raises(SvcAuthError, match="replay window"):
        verify_headers(h, "POST", "/v1/entries", b'{"x":1}', get_pubkey,
                       now=1000000.0 + MAX_SKEW_S + 1)


def test_unknown_service_rejected():
    h = _signed()
    h["X-Truvo-Svc"] = "rogue-svc"
    with pytest.raises(SvcAuthError):
        verify_headers(h, "POST", "/v1/entries", b'{"x":1}',
                       lambda s: (_ for _ in ()).throw(KeyError(s)),
                       now=1000000.0)


def test_wrong_key_rejected():
    other_priv, _ = generate_keypair()
    h = sign_headers("scoring-svc", other_priv, "POST", "/v1/entries",
                     b'{"x":1}', now=1000000.0)
    with pytest.raises(SvcAuthError, match="verification failed"):
        verify_headers(h, "POST", "/v1/entries", b'{"x":1}', get_pubkey,
                       now=1000000.0)


def test_missing_headers_rejected():
    with pytest.raises(SvcAuthError, match="missing"):
        verify_headers({}, "POST", "/v1/entries", b"", get_pubkey)

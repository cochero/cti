"""Object store live: content-addressing, idempotency, self-verification.

Env: TRUVO_OBJSTORE_ENDPOINT (dev MinIO localhost:9000).
"""

import hashlib
import os
import uuid

import pytest

ENDPOINT = os.environ.get("TRUVO_OBJSTORE_ENDPOINT")

pytestmark = pytest.mark.skipif(
    not ENDPOINT, reason="TRUVO_OBJSTORE_ENDPOINT not set"
)

if ENDPOINT:
    from truvo_objstore import ContentHashMismatch, ObjectStore


@pytest.fixture()
def store():
    return ObjectStore(bucket="truvo-test-%s" % uuid.uuid4().hex[:12])


def test_put_returns_sha256_key(store):
    data = b"hello threat intel %s" % uuid.uuid4().hex.encode()
    key, size = store.put(data)
    assert key == hashlib.sha256(data).hexdigest()
    assert size == len(data)


def test_get_roundtrip(store):
    data = b'{"cve": "CVE-2026-0001"}'
    key, _ = store.put(data, content_type="application/json")
    assert store.get(key) == data


def test_put_is_idempotent(store):
    data = b"same bytes"
    k1, _ = store.put(data)
    k2, _ = store.put(data)
    assert k1 == k2


def test_get_verifies_content(store):
    """A key whose object doesn't hash to it must never return bytes."""
    data = b"trustworthy"
    key, _ = store.put(data)
    # forge a mismatch: put different bytes under a lie of a key by
    # writing directly through the client
    fake_key = "0" * 64
    store._ensure_bucket()
    import io as _io
    store._client.put_object(store.bucket, fake_key, _io.BytesIO(b"tampered"), 8)
    with pytest.raises(ContentHashMismatch):
        store.get(fake_key)
    assert store.get(key) == data  # honest object still fine

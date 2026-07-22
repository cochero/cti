"""Per-tenant anchor keys live (S7): keys come from the vault, differ per
tenant, and survive process restarts (vault is the source of truth).

Env: TRUVO_TEST_DATABASE_URL + TRUVO_VAULT_ADDR/TOKEN.
"""

import os
import uuid

import pytest

ADMIN_URL = os.environ.get("TRUVO_TEST_DATABASE_URL")
VAULT = os.environ.get("TRUVO_VAULT_ADDR")

pytestmark = pytest.mark.skipif(
    not (ADMIN_URL and VAULT), reason="db/vault env not set"
)

if ADMIN_URL and VAULT:
    from app.anchor import _key_cache, make_anchor, verify_anchor_signature
    from truvo_secrets import SecretsClient


def test_keys_differ_per_tenant():
    t1, t2 = str(uuid.uuid4()), str(uuid.uuid4())
    a1 = make_anchor(t1, "2026-07-23T00:00:00Z", 0, "a" * 64)
    a2 = make_anchor(t2, "2026-07-23T00:00:00Z", 0, "a" * 64)
    # identical content, different tenants -> different signatures
    assert a1.signature != a2.signature
    assert verify_anchor_signature(a1) and verify_anchor_signature(a2)


def test_key_persisted_in_vault_and_stable_across_cache_loss():
    tenant = str(uuid.uuid4())
    a1 = make_anchor(tenant, "2026-07-23T00:00:00Z", 0, "b" * 64)

    stored = SecretsClient().kv_get("secret", "truvo/tenants/%s" % tenant)
    assert "anchor_key" in stored

    _key_cache.clear()  # simulate service restart
    a2 = make_anchor(tenant, "2026-07-23T00:00:00Z", 0, "b" * 64)
    assert a1.signature == a2.signature  # same vault key -> same signature


def test_tampered_vault_key_invalidates_old_anchors():
    """Key rotation semantics: an anchor signed under the old key fails
    verification under the new one (rotation implies re-anchoring)."""
    tenant = str(uuid.uuid4())
    a1 = make_anchor(tenant, "2026-07-23T00:00:00Z", 0, "c" * 64)

    SecretsClient().kv_put(
        "secret", "truvo/tenants/%s" % tenant, {"anchor_key": "rotated-key"}
    )
    _key_cache.clear()
    assert not verify_anchor_signature(a1)

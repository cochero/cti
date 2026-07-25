"""truvo_secrets: ref-parsing units + live KV round-trip when vault env set."""

import os
import uuid

import pytest
from truvo_secrets import SecretRefError, SecretsClient, resolve

VAULT = os.environ.get("TRUVO_VAULT_ADDR")

# --- unit: ref grammar ------------------------------------------------------

def test_env_ref(monkeypatch):
    monkeypatch.setenv("MY_TEST_SECRET", "s3cr3t")
    assert resolve("env:MY_TEST_SECRET") == "s3cr3t"


def test_env_ref_missing():
    with pytest.raises(SecretRefError, match="not set"):
        resolve("env:DOES_NOT_EXIST_%s" % uuid.uuid4().hex[:8])


def test_plaintext_rejected():
    with pytest.raises(SecretRefError, match="unsupported"):
        resolve("hunter2")


def test_malformed_vault_ref_rejected():
    with pytest.raises(SecretRefError, match="needs"):
        resolve("vault:no-field-or-slash")


# --- live: KV v2 round-trip -------------------------------------------------

@pytest.mark.skipif(not VAULT, reason="TRUVO_VAULT_ADDR not set")
def test_kv_roundtrip_and_resolution():
    client = SecretsClient()
    path = "truvo-test/%s" % uuid.uuid4().hex[:12]
    client.kv_put("secret", path, {"api_key": "k-123", "other": "x"})

    assert client.kv_get("secret", path)["api_key"] == "k-123"
    assert resolve("vault:secret/%s#api_key" % path, client) == "k-123"

    with pytest.raises(SecretRefError, match="absent"):
        resolve("vault:secret/%s#missing_field" % path, client)


@pytest.mark.skipif(not VAULT, reason="TRUVO_VAULT_ADDR not set")
def test_missing_secret_raises_keyerror():
    with pytest.raises(KeyError):
        SecretsClient().kv_get("secret", "truvo-test/absent-%s" % uuid.uuid4().hex)

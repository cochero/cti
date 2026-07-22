"""Minimal Vault-API (KV v2) client + secret-reference resolution.

Works against OpenBao and HashiCorp Vault alike. Auth is token-based:
dev uses the compose root token; staging/prod use Kubernetes auth to
obtain short-lived tokens (ADR-0005) — this client only ever sees a token
string either way.

Secret references — the only two forms allowed anywhere in TRUVO config:
    vault:<mount>/<path>#<field>   e.g. vault:secret/truvo/svc/ledger#anchor_key
    env:<NAME>                     dev/test fallback
Raw secrets in config files or request bodies are a review-blocking
defect once a component has migrated to refs.
"""

import os
from typing import Any, Dict, Optional

import requests

__all__ = ["SecretsClient", "SecretRefError", "resolve"]


class SecretRefError(ValueError):
    pass


class SecretsClient:
    def __init__(self, addr: Optional[str] = None, token: Optional[str] = None,
                 timeout: float = 10.0):
        self.addr = (addr or os.environ.get("TRUVO_VAULT_ADDR", "")).rstrip("/")
        self.token = token or os.environ.get("TRUVO_VAULT_TOKEN", "")
        self.timeout = timeout
        if not self.addr:
            raise SecretRefError("TRUVO_VAULT_ADDR not configured")

    def _headers(self) -> Dict[str, str]:
        return {"X-Vault-Token": self.token}

    def kv_get(self, mount: str, path: str) -> Dict[str, Any]:
        resp = requests.get(
            "%s/v1/%s/data/%s" % (self.addr, mount, path),
            headers=self._headers(), timeout=self.timeout,
        )
        if resp.status_code == 404:
            raise KeyError("secret not found: %s/%s" % (mount, path))
        resp.raise_for_status()
        return resp.json()["data"]["data"]

    def kv_put(self, mount: str, path: str, data: Dict[str, Any]) -> None:
        resp = requests.post(
            "%s/v1/%s/data/%s" % (self.addr, mount, path),
            headers=self._headers(), json={"data": data}, timeout=self.timeout,
        )
        resp.raise_for_status()


def resolve(ref: str, client: Optional[SecretsClient] = None) -> str:
    """Resolve a secret reference to its value. See module docstring for
    the two allowed forms; anything else raises."""
    if ref.startswith("env:"):
        name = ref[4:]
        value = os.environ.get(name)
        if value is None:
            raise SecretRefError("env secret %r not set" % name)
        return value
    if ref.startswith("vault:"):
        body = ref[6:]
        if "#" not in body or "/" not in body:
            raise SecretRefError("vault ref needs <mount>/<path>#<field>: %r" % ref)
        path_part, field = body.rsplit("#", 1)
        mount, path = path_part.split("/", 1)
        data = (client or SecretsClient()).kv_get(mount, path)
        if field not in data:
            raise SecretRefError("field %r absent in %s" % (field, path_part))
        return str(data[field])
    raise SecretRefError(
        "unsupported secret ref %r (allowed: vault:, env:)" % ref[:24]
    )

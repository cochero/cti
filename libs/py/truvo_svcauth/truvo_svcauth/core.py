"""Service-to-service request authentication (S7, Architecture v2 SS8.3).

Every internal mutating call carries an Ed25519 signature over a canonical
digest of (service, timestamp, method, path, body). Verifiers fetch public
keys from the vault (`secret/truvo/services/<svc>#pubkey`) — possession of
network access is not identity; possession of a vault-provisioned private
key is.

This is the code-level identity layer; transport mTLS (SPIFFE mesh) is
added at the deployment layer in staging (ADR-0005). Defense in depth:
both survive the other's misconfiguration.

Replay: signatures embed a timestamp; verifiers reject outside a ±300s
window. Idempotent APIs (the only kind services expose internally) make
in-window replay harmless; a nonce cache can tighten this later without
protocol change.
"""

import base64
import hashlib
import time
from typing import Callable, Dict, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from truvo_core.canonical import canonical_json

__all__ = [
    "generate_keypair", "sign_headers", "verify_headers", "SvcAuthError",
    "MAX_SKEW_S",
]

MAX_SKEW_S = 300


class SvcAuthError(ValueError):
    pass


def generate_keypair() -> Tuple[str, str]:
    """Returns (private_b64, public_b64)."""
    priv = Ed25519PrivateKey.generate()
    priv_raw = priv.private_bytes_raw()
    pub_raw = priv.public_key().public_bytes_raw()
    return (
        base64.b64encode(priv_raw).decode(),
        base64.b64encode(pub_raw).decode(),
    )


def _digest(svc: str, ts: str, method: str, path: str, body: bytes) -> bytes:
    return canonical_json(
        {
            "svc": svc,
            "ts": ts,
            "method": method.upper(),
            "path": path,
            "body_sha256": hashlib.sha256(body).hexdigest(),
        }
    )


def sign_headers(
    svc: str, private_b64: str, method: str, path: str, body: bytes,
    now: Optional[float] = None,
) -> Dict[str, str]:
    ts = str(int(now if now is not None else time.time()))
    priv = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_b64))
    sig = priv.sign(_digest(svc, ts, method, path, body))
    return {
        "X-Truvo-Svc": svc,
        "X-Truvo-Ts": ts,
        "X-Truvo-Sig": base64.b64encode(sig).decode(),
    }


def verify_headers(
    headers: Dict[str, str], method: str, path: str, body: bytes,
    get_pubkey: Callable[[str], str],
    now: Optional[float] = None,
) -> str:
    """Verify and return the calling service name. Raises SvcAuthError."""
    svc = headers.get("X-Truvo-Svc") or headers.get("x-truvo-svc")
    ts = headers.get("X-Truvo-Ts") or headers.get("x-truvo-ts")
    sig_b64 = headers.get("X-Truvo-Sig") or headers.get("x-truvo-sig")
    if not (svc and ts and sig_b64):
        raise SvcAuthError("missing service identity headers")
    try:
        skew = abs((now if now is not None else time.time()) - int(ts))
    except ValueError:
        raise SvcAuthError("bad timestamp")
    if skew > MAX_SKEW_S:
        raise SvcAuthError("timestamp outside replay window (%.0fs)" % skew)
    try:
        pub = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(get_pubkey(svc))
        )
        pub.verify(base64.b64decode(sig_b64), _digest(svc, ts, method, path, body))
    except SvcAuthError:
        raise
    except Exception:
        raise SvcAuthError("signature verification failed for %r" % svc)
    return svc

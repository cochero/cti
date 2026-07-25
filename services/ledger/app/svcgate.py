"""Service-identity gate for mutating endpoints (S7, Arch SS8.3).

Enforcement is staged: TRUVO_SVCAUTH=1 turns it on (staging default once
all callers sign; then always-on). Public keys come from the vault at
`secret/truvo/services/<svc>#pubkey`, cached with a short TTL so key
rotation propagates without restarts.
"""

import os
import time
from typing import Dict, Tuple

from fastapi import HTTPException, Request
from truvo_svcauth import SvcAuthError, verify_headers

_PUBKEY_TTL_S = 60
_pubkey_cache: Dict[str, Tuple[str, float]] = {}


def _get_pubkey(svc: str) -> str:
    now = time.time()
    hit = _pubkey_cache.get(svc)
    if hit and now - hit[1] < _PUBKEY_TTL_S:
        return hit[0]
    from truvo_secrets import SecretsClient

    key = SecretsClient().kv_get("secret", "truvo/services/%s" % svc)["pubkey"]
    _pubkey_cache[svc] = (key, now)
    return key


async def require_service_identity(request: Request) -> str:
    """FastAPI dependency. Returns the verified calling service name, or
    "anonymous" while enforcement is off."""
    if os.environ.get("TRUVO_SVCAUTH") != "1":
        return "anonymous"
    body = await request.body()
    try:
        return verify_headers(
            dict(request.headers), request.method, request.url.path, body,
            _get_pubkey,
        )
    except (SvcAuthError, KeyError) as exc:
        raise HTTPException(status_code=401, detail="service auth: %s" % exc) from exc

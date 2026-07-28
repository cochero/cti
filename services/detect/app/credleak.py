"""Credential-leak matching — domain-scoped, PII-minimizing (Arch §11.3).

The binding rule: we surface ONLY credentials whose domain is one the
customer registered. We do not warehouse the internet's stolen PII — a
breach record for a domain no customer registered is dropped, never stored.
And we never persist a cleartext credential: only a salted hash, so a leak
of OUR database does not re-leak the customer's passwords.

Pure core; the service supplies the registered-domain set and the salt.
"""

import hashlib
from typing import Dict, Iterable, List, Set, Tuple

__all__ = ["salt_credential", "scan_breach"]


def salt_credential(cleartext: str, salt: str) -> str:
    """Salted SHA-256 of a credential. The cleartext is never returned or
    stored — only this digest."""
    return hashlib.sha256((salt + ":" + cleartext).encode()).hexdigest()


def _split_email(email: str) -> Tuple[str, str]:
    local, _, domain = email.partition("@")
    return local.strip().lower(), domain.strip().lower()


def scan_breach(records: Iterable[Dict[str, str]],
                registered_domains: Set[str],
                salt: str) -> List[Dict[str, str]]:
    """records: [{"email": ..., "credential": ...}]. Returns hits ONLY for
    registered domains, each with a SALTED HASH (never the cleartext).

    Everything outside the registered-domain scope is dropped here and never
    reaches storage — that is the §11.3 guarantee, enforced in code."""
    domains = {d.strip().lower() for d in registered_domains}
    hits: List[Dict[str, str]] = []
    for rec in records:
        local, domain = _split_email(rec.get("email", ""))
        if not domain or domain not in domains:
            continue   # not our customer's asset -> ignore entirely
        cred = rec.get("credential", "")
        hits.append({
            "local_part": local,
            "domain": domain,
            "cred_salted_sha256": salt_credential(cred, salt),
            # NOTE: no cleartext credential field, by construction
        })
    return hits

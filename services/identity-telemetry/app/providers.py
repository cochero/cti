"""Identity providers — read-only sync sources (Architecture v2 SS4.2).

Every provider yields normalized Identity records. EntraProvider speaks
Microsoft Graph with client-credential auth (read-only scopes only:
User.Read.All, RoleManagement.Read.Directory — we hold no write scopes by
design). FakeProvider is the deterministic test double.

NOTE: EntraProvider is verified against Graph API *contracts*, not a live
tenant, until a design-partner tenant exists (tracked in the service
README). The sync pipeline, storage, RLS, and blast-radius math are fully
live-tested via FakeProvider.
"""

from dataclasses import dataclass, field
from typing import Iterable, List, Protocol

import requests

__all__ = ["Identity", "IdentityProvider", "EntraProvider", "FakeProvider"]

# Entra directory role templates considered privileged (subset; the full
# curated map is intel-team-maintained data, not code)
PRIVILEGED_ENTRA_ROLES = {
    "Global Administrator", "Privileged Role Administrator",
    "Security Administrator", "Exchange Administrator",
    "SharePoint Administrator", "User Administrator",
    "Application Administrator", "Cloud Application Administrator",
    "Hybrid Identity Administrator", "Intune Administrator",
}


@dataclass(frozen=True)
class Identity:
    principal_id: str
    kind: str                 # user | service | group
    display: str = ""
    privileged: bool = False
    roles: List[str] = field(default_factory=list)


class IdentityProvider(Protocol):
    source: str

    def fetch_identities(self) -> Iterable[Identity]: ...


class EntraProvider:
    source = "entra"

    def __init__(self, idp_tenant_id: str, client_id: str, client_secret: str,
                 timeout: float = 30.0):
        self._token_url = (
            "https://login.microsoftonline.com/%s/oauth2/v2.0/token" % idp_tenant_id
        )
        self._client_id = client_id
        self._client_secret = client_secret
        self._timeout = timeout

    def _token(self) -> str:
        resp = requests.post(
            self._token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "scope": "https://graph.microsoft.com/.default",
            },
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    def _get_all(self, url: str, headers: dict) -> List[dict]:
        items: List[dict] = []
        while url:
            resp = requests.get(url, headers=headers, timeout=self._timeout)
            resp.raise_for_status()
            data = resp.json()
            items.extend(data.get("value", []))
            url = data.get("@odata.nextLink", "")
        return items

    def fetch_identities(self) -> Iterable[Identity]:
        headers = {"Authorization": "Bearer %s" % self._token()}
        graph = "https://graph.microsoft.com/v1.0"

        # role assignments first: principal_id -> role names
        role_map: dict = {}
        for role in self._get_all("%s/directoryRoles" % graph, headers):
            name = role.get("displayName", "")
            for member in self._get_all(
                "%s/directoryRoles/%s/members" % (graph, role["id"]), headers
            ):
                role_map.setdefault(member["id"], []).append(name)

        for u in self._get_all(
            "%s/users?$select=id,displayName,accountEnabled" % graph, headers
        ):
            if not u.get("accountEnabled", True):
                continue
            roles = sorted(role_map.get(u["id"], []))
            yield Identity(
                principal_id=u["id"], kind="user",
                display=u.get("displayName", ""),
                privileged=any(r in PRIVILEGED_ENTRA_ROLES for r in roles),
                roles=roles,
            )
        for sp in self._get_all(
            "%s/servicePrincipals?$select=id,displayName" % graph, headers
        ):
            roles = sorted(role_map.get(sp["id"], []))
            yield Identity(
                principal_id=sp["id"], kind="service",
                display=sp.get("displayName", ""),
                privileged=any(r in PRIVILEGED_ENTRA_ROLES for r in roles),
                roles=roles,
            )


class FakeProvider:
    """Deterministic test double with a realistic privilege mix."""

    source = "fake"

    def __init__(self, identities: List[Identity]):
        self._identities = identities

    def fetch_identities(self) -> Iterable[Identity]:
        return list(self._identities)

"""OIDC claims mapping (Entra ID / Okta).

Active only when TRUVO_OIDC_ENABLED=1. Users are provisioned on first
login; tenant membership is NOT auto-granted -- a tenant admin assigns it
(joining an IdP does not entitle anyone to intel).
"""

from mozilla_django_oidc.auth import OIDCAuthenticationBackend


class TruvoOIDCBackend(OIDCAuthenticationBackend):
    def create_user(self, claims):
        user = super().create_user(claims)
        user.username = claims.get("preferred_username", user.email)
        user.first_name = claims.get("given_name", "")
        user.last_name = claims.get("family_name", "")
        user.save()
        return user

    def update_user(self, user, claims):
        user.first_name = claims.get("given_name", user.first_name)
        user.last_name = claims.get("family_name", user.last_name)
        user.save()
        return user

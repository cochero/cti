"""Users and tenant memberships (RBAC).

Django owns these tables (its migrations create them). They are core
platform config, not tenant-scoped data rows, so they are not RLS-fenced
(ADR-0003); the core service legitimately sees all memberships to route
users. Tenant-scoped *data* lives in SQL-first RLS tables.
"""

import uuid

from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    """Email-first user. SSO (OIDC) populates these; local dev uses admin."""

    email = models.EmailField(unique=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]

    def __str__(self) -> str:
        return self.email


class Membership(models.Model):
    """Grants a user a role within a tenant. A user may belong to several
    tenants (MSP analysts); exactly one membership may be their default."""

    class Role(models.TextChoices):
        ADMIN = "admin", "Tenant admin"
        ANALYST = "analyst", "SOC analyst"
        VIEWER = "viewer", "Read-only viewer"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="memberships")
    tenant_id = models.UUIDField()  # FK enforced in SQL layer; registry is SQL-first
    role = models.CharField(max_length=16, choices=Role.choices)
    is_default = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["user", "tenant_id"], name="uniq_membership_user_tenant"
            ),
            models.UniqueConstraint(
                fields=["user"],
                condition=models.Q(is_default=True),
                name="uniq_default_membership_per_user",
            ),
        ]

    def __str__(self) -> str:
        return "%s @ %s (%s)" % (self.user_id, self.tenant_id, self.role)

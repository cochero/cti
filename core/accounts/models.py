"""Users and tenant memberships (RBAC).

Django owns these tables (its migrations create them). They are core
platform config, not tenant-scoped data rows, so they are not RLS-fenced
(ADR-0003); the core service legitimately sees all memberships to route
users. Tenant-scoped *data* lives in SQL-first RLS tables.
"""

import hashlib
import uuid
from datetime import timedelta

import django.utils.timezone as timezone
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


def _ip_hash(ip: str) -> str:
    return hashlib.sha256((ip or "").encode("utf-8")).hexdigest()[:16]


class LoginFailure(models.Model):
    """Failed-login ledger for account lockout (security review H1).

    Email lowercased; IP stored only as a truncated hash for correlation
    (privacy: not useful alone). Sliding window, prune after 24h.

    The brute-force alerting hook reads the same rows: once the
    observability stack lands, failure-rate spikes are one query away.
    """

    id = models.BigAutoField(primary_key=True)
    email = models.EmailField(db_index=True)
    ip_hash = models.CharField(max_length=16, default="")
    failed_at = models.DateTimeField(auto_now_add=True, db_index=True)

    @classmethod
    def record(cls, email: str, ip: str) -> None:
        cls.objects.create(email=email.lower(), ip_hash=_ip_hash(ip))

    @classmethod
    def prune(cls) -> None:
        horizon = timezone.now() - timedelta(hours=24)
        cls.objects.filter(failed_at__lt=horizon).delete()

    @classmethod
    def locked_out(cls, email: str, max_failures: int,
                   window_seconds: int) -> bool:
        since = timezone.now() - timedelta(seconds=window_seconds)
        return cls.objects.filter(
            email=email.lower(), failed_at__gte=since
        ).count() >= max_failures

    @classmethod
    def clear(cls, email: str) -> None:
        cls.objects.filter(email=email.lower()).delete()

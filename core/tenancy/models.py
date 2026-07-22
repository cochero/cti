"""Read models over the SQL-first tenancy tables (ADR-0003).

managed = False everywhere: db/migrations owns these schemas. Django maps
onto them; it can never migrate (and therefore never weaken) them.
"""

from django.db import models


class Tenant(models.Model):
    tenant_id = models.UUIDField(primary_key=True)
    slug = models.SlugField(unique=True)
    name = models.TextField()
    status = models.TextField()
    created_at = models.DateTimeField()

    class Meta:
        managed = False
        db_table = "tenants"

    def __str__(self) -> str:
        return self.slug


class LedgerEntry(models.Model):
    """Tenant-scoped, RLS-fenced, append-only (db/migrations/0003).

    Reads through this model return only the request tenant's rows when the
    connection role is `truvo_app` and TenantContextMiddleware has set the
    tenant — the fence is Postgres, not this class.
    """

    pk = models.CompositePrimaryKey("tenant_id", "seq")
    tenant_id = models.UUIDField()
    seq = models.BigIntegerField()
    ts_iso = models.TextField()
    actor = models.TextField()
    kind = models.TextField()
    payload = models.JSONField(default=dict)
    prev_hash = models.CharField(max_length=64)
    entry_hash = models.CharField(max_length=64)

    class Meta:
        managed = False
        db_table = "ledger_entries"
        ordering = ["seq"]

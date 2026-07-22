"""Tenant context middleware.

Sets `truvo.tenant_id` on the request's database connection so every RLS
policy (db/README.md) fences this request to the user's tenant. Clears it
after the response so pooled connections never carry stale context.

The middleware selects the tenant; Postgres enforces it. If this
middleware is buggy or bypassed, the failure mode is *zero rows*, never
another tenant's rows (unset context -> NULL -> policies match nothing).
"""

from django.db import connection


def _set_tenant(tenant_id: str) -> None:
    with connection.cursor() as cur:
        cur.execute("SELECT set_config('truvo.tenant_id', %s, false)", [tenant_id])


class TenantContextMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        tenant_id = None
        user = getattr(request, "user", None)
        if user is not None and user.is_authenticated:
            membership = (
                user.memberships.filter(is_default=True).first()
                or user.memberships.first()
            )
            if membership is not None:
                tenant_id = str(membership.tenant_id)
                request.tenant_id = tenant_id
                request.membership = membership
                _set_tenant(tenant_id)
        try:
            return self.get_response(request)
        finally:
            if tenant_id is not None:
                _set_tenant("")

from django.contrib import admin
from django.urls import include, path
from tenancy.api import LedgerEntryListView, TenantMeView

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/v1/tenants/me", TenantMeView.as_view(), name="tenant-me"),
    path("api/v1/ledger/entries", LedgerEntryListView.as_view(), name="ledger-entries"),
]

from django.conf import settings  # noqa: E402

if settings.OIDC_ENABLED:
    urlpatterns.append(path("oidc/", include("mozilla_django_oidc.urls")))

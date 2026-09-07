from django.contrib import admin
from django.urls import include, path
from tenancy.api import LedgerEntryListView, TenantMeView
from tenancy.mis import (
    AttackHeatmapView,
    DashboardSummaryView,
    LoginView,
    LogoutView,
    PrioritiesView,
    PriorityDecompositionView,
    RulesView,
    RuleTransitionView,
)
from tenancy.onboarding import (
    LegalDocsView,
    OnboardingAdminView,
    OnboardingCompleteView,
    OnboardingDetailView,
    OnboardingEnvironmentView,
    OnboardingLegalView,
    OnboardingListView,
)

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/v1/tenants/me", TenantMeView.as_view(), name="tenant-me"),
    path("api/v1/ledger/entries", LedgerEntryListView.as_view(), name="ledger-entries"),
    # MIS: analyst console + CISO dashboard (Architecture §4.2 presentation)
    path("api/v1/priorities", PrioritiesView.as_view(), name="priorities"),
    path("api/v1/priorities/<str:cve>/decomposition",
         PriorityDecompositionView.as_view(), name="priority-decomposition"),
    path("api/v1/rules", RulesView.as_view(), name="rules"),
    path("api/v1/rules/<uuid:rule_id>/transition",
         RuleTransitionView.as_view(), name="rule-transition"),
    path("api/v1/attack-heatmap", AttackHeatmapView.as_view(),
         name="attack-heatmap"),
    path("api/v1/dashboard/summary", DashboardSummaryView.as_view(),
         name="dashboard-summary"),
    # SPA session auth (unused when OIDC/SSO fronts the deployment)
    path("api/v1/auth/login", LoginView.as_view(), name="auth-login"),
    path("api/v1/auth/logout", LogoutView.as_view(), name="auth-logout"),
    # Onboarding wizard (platform staff)
    path("api/v1/onboarding", OnboardingListView.as_view(), name="onboarding"),
    path("api/v1/onboarding/legal-docs", LegalDocsView.as_view(),
         name="onboarding-legal-docs"),
    path("api/v1/onboarding/<uuid:tenant_id>", OnboardingDetailView.as_view(),
         name="onboarding-detail"),
    path("api/v1/onboarding/<uuid:tenant_id>/legal",
         OnboardingLegalView.as_view(), name="onboarding-legal"),
    path("api/v1/onboarding/<uuid:tenant_id>/admin",
         OnboardingAdminView.as_view(), name="onboarding-admin"),
    path("api/v1/onboarding/<uuid:tenant_id>/environment",
         OnboardingEnvironmentView.as_view(), name="onboarding-environment"),
    path("api/v1/onboarding/<uuid:tenant_id>/complete",
         OnboardingCompleteView.as_view(), name="onboarding-complete"),
]

from django.conf import settings  # noqa: E402

if settings.OIDC_ENABLED:
    urlpatterns.append(path("oidc/", include("mozilla_django_oidc.urls")))

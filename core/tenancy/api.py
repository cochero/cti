"""MIS API v1 — first endpoints proving the Django-over-RLS integration."""

from rest_framework import serializers
from rest_framework.exceptions import PermissionDenied
from rest_framework.generics import ListAPIView
from rest_framework.response import Response
from rest_framework.views import APIView

from tenancy.models import LedgerEntry


class RequireMembership:
    """Mixin: any MIS endpoint needs a resolved tenant context."""

    def check_membership(self, request):
        if getattr(request, "tenant_id", None) is None:
            raise PermissionDenied("no tenant membership")


class TenantMeView(RequireMembership, APIView):
    def get(self, request):
        self.check_membership(request)
        return Response(
            {
                "tenant_id": request.tenant_id,
                "role": request.membership.role,
                "user": request.user.email,
            }
        )


class LedgerEntrySerializer(serializers.ModelSerializer):
    class Meta:
        model = LedgerEntry
        fields = ["tenant_id", "seq", "ts_iso", "actor", "kind", "payload", "entry_hash"]


class LedgerEntryListView(RequireMembership, ListAPIView):
    serializer_class = LedgerEntrySerializer

    def get_queryset(self):
        self.check_membership(self.request)
        # No tenant filter here — deliberately. The RLS policy is the fence;
        # this endpoint returning only the caller's rows is what
        # tests_live/test_rls_via_django.py proves.
        return LedgerEntry.objects.all()

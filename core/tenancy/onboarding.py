"""Tenant onboarding — the operator wizard that turns a company into a tenant.

Full process, every step ledger-recorded (Architecture §11 legal, §12):

    basics (company + profile) -> legal (versioned acceptances) ->
    admin (first administrator) -> environment (stack, domains, IdP) ->
    review -> ACTIVATE

Two isolation disciplines meet here:
  - onboarding_records is platform metadata (no RLS, staff-only API);
  - everything tenant-scoped it writes (assets, watch domains, ledger
    entries) is RLS-fenced, so each write runs under the TARGET tenant's
    context inside its own transaction — set_config(..., true) reverts
    with the transaction, never leaking across requests.

Legal acceptances cite exact document versions and land on the tenant's
hash-chained ledger: provable, replayable consent — the compliance asset
the platform sells, applied to itself.
"""

import json
import re
import uuid
from datetime import datetime, timezone

from rest_framework import status
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView

from .mis import _ledger_append

# ---------------------------------------------------------------- legal docs

LEGAL_DOCS = {
    "dpa": {
        "id": "dpa", "version": "1.0", "title": "Data Processing Agreement",
        "required": True,
        "body": (
            "DATA PROCESSING AGREEMENT — v1.0\n"
            "\n"
            "1. Roles. Customer is the controller; TRUVO operates as processor "
            "for personal data processed on Customer's behalf. For global "
            "threat-intelligence corpora processed independently of Customer "
            "data, TRUVO is controller.\n"
            "\n"
            "2. Processing scope. (a) Processing of Customer-registered asset "
            "and identity metadata for prioritization and blast-radius "
            "analysis; (b) credential-leak monitoring limited to domains "
            "registered by Customer; (c) detection-content telemetry "
            "originating from Customer's integrated environment.\n"
            "\n"
            "3. Subprocessors. Infrastructure hosting, object storage, and "
            "message-broking providers as listed in the current subprocessor "
            "register; 30 days' notice before additions.\n"
            "\n"
            "4. Security measures. TLS 1.3 in transit; AES-256 at rest; "
            "per-tenant encryption keys (crypto-shredding on offboarding); "
            "row-level security isolation verified by automated cross-tenant "
            "leak tests; append-only hash-chained audit ledger.\n"
            "\n"
            "5. Breach notification. TRUVO notifies Customer without undue "
            "delay and within 72 hours of confirming a personal-data breach "
            "affecting Customer data.\n"
            "\n"
            "6. Data-subject rights. TRUVO assists Customer in responding to "
            "data-subject requests within the scope of processed metadata.\n"
            "\n"
            "7. Retention and deletion. Raw collected artifacts 13 months; "
            "scores and ledger entries 7 years (compliance records); leaked "
            "credentials stored only as salted hashes and purged on the "
            "configured schedule; full tenant deletion via crypto-shred plus "
            "row purge on verified request.\n"
        ),
    },
    "tos": {
        "id": "tos", "version": "1.0", "title": "Terms of Service",
        "required": True,
        "body": (
            "TERMS OF SERVICE — v1.0\n"
            "\n"
            "1. Service. TRUVO provides threat prioritization, detection "
            "engineering, and monitoring as described in the order form. "
            "TRUVO arms the customer's existing SIEM/EDR; it is not a SIEM "
            "replacement.\n"
            "\n"
            "2. Autonomous actions. Outbound actions are human-gated by "
            "default. Tier-1 autonomy, where enabled, is bounded by "
            "hardcoded circuit breakers (velocity, blast radius, novelty) "
            "and is revocable per integration at any time.\n"
            "\n"
            "3. Acceptable use. Customer will not attempt to poison, "
            "inject, or otherwise manipulate the intelligence pipeline, and "
            "will use credentials and integrations only for its own "
            "environment.\n"
            "\n"
            "4. Availability. Target 99.9% monthly for the SaaS profile. "
            "Scheduled maintenance announced 72 hours ahead.\n"
            "\n"
            "5. Liability. Service is provided on a best-efforts basis "
            "consistent with industry standards; aggregate liability is "
            "capped at fees paid in the preceding 12 months.\n"
            "\n"
            "6. Termination and offboarding. On termination: staged "
            "detection content is withdrawn from Customer environments, "
            "tenant data crypto-shredded, export package provided where "
            "technically available.\n"
        ),
    },
    "data_governance": {
        "id": "data_governance", "version": "1.0",
        "title": "Data Governance & PII Policy", "required": True,
        "body": (
            "DATA GOVERNANCE & PII POLICY — v1.0\n"
            "\n"
            "1. Credential-leak monitoring scope. Monitoring ingests ONLY "
            "domains registered by the Customer. The platform does not "
            "warehouse the internet's stolen credentials.\n"
            "\n"
            "2. Hashed storage. Discovered credentials are stored as salted "
            "hashes plus metadata; cleartext is never persisted. Purge "
            "schedule configurable per tenant.\n"
            "\n"
            "3. PII minimization at extraction. The extraction schema has no "
            "fields for irrelevant personal data; what cannot be represented "
            "cannot be stored.\n"
            "\n"
            "4. Cross-tenant isolation. Shared models train only on global "
            "open data. Tenant-derived indexes are physically per-tenant. "
            "Cross-tenant statistics are published only as k-anonymized "
            "aggregates (k>=5).\n"
            "\n"
            "5. Air-gap profiles. On air-gapped deployments no telemetry of "
            "any kind leaves the Customer environment; diagnostics are "
            "exportable bundles the Customer reviews.\n"
        ),
    },
}

SECTORS = [
    "finance", "healthcare", "energy", "manufacturing", "government",
    "telecom", "retail", "technology", "transport", "education", "other",
]

DEPLOYMENT_PROFILES = ["saas", "vpc", "airgap"]
_CPE_RE = re.compile(r"^cpe:2\.3:[aho]:(?P<ven>[^:]+):(?P<pro>[^:]+)")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63})+$", re.I)
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$")


# ---------------------------------------------------------------- helpers

def _staff(request):
    if not request.user.is_staff:
        raise PermissionDenied("onboarding is a platform-staff function")


def _rows(sql, params=None):
    from django.db import connection
    with connection.cursor() as cur:
        cur.execute(sql, params or [])
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, row, strict=False)) for row in cur.fetchall()]


def _record(tenant_id):
    rows = _rows(
        "SELECT tenant_id, status, current_step, state, legal, created_by,"
        " created_at, completed_at FROM onboarding_records WHERE tenant_id = %s",
        [str(tenant_id)],
    )
    if not rows:
        return None
    r = rows[0]
    r["state"] = _j(r["state"])
    r["legal"] = _j(r["legal"])
    return r


def _j(v):
    return json.loads(v) if isinstance(v, str) else (v or {})


def _as_tenant(tenant_id, fn):
    """Run fn(cur) under the TARGET tenant's RLS context, inside a Django
    managed transaction. set_config(..., true) scopes the context to the
    transaction; the finally-reset clears it before the block exits so no
    context survives into later queries on this connection."""
    from django.db import connection, transaction
    with transaction.atomic():
        with connection.cursor() as cur:
            cur.execute("SELECT set_config('truvo.tenant_id', %s, true)",
                        [str(tenant_id)])
            try:
                return fn(cur)
            finally:
                cur.execute("SELECT set_config('truvo.tenant_id', '', true)")


def _update_record(tenant_id, **cols):
    from django.db import connection
    sets = ", ".join("%s = %%s" % c for c in cols)
    with connection.cursor() as cur:
        cur.execute("UPDATE onboarding_records SET %s WHERE tenant_id = %%s"
                    % sets, [*cols.values(), str(tenant_id)])


def _slugify(name):
    s = re.sub(r"[^a-z0-9-]+", "-", name.strip().lower()).strip("-")
    return s[:40] or "tenant"


# ---------------------------------------------------------------- views

class LegalDocsView(APIView):
    """The versioned legal corpus the wizard renders. Version bumps happen
    here and ONLY here; acceptances cite what this registry served."""

    def get(self, request):
        return Response({"docs": list(LEGAL_DOCS.values())})


class OnboardingListView(APIView):
    def get(self, request):
        _staff(request)
        rows = _rows(
            "SELECT r.tenant_id, r.status, r.current_step, r.state, r.legal,"
            " r.created_by, r.created_at, r.completed_at, t.name"
            " FROM onboarding_records r JOIN tenants t"
            "   ON t.tenant_id = r.tenant_id"
            " ORDER BY r.created_at DESC LIMIT 100")
        for r in rows:
            r["state"] = _j(r["state"])
            r["legal"] = _j(r["legal"])
        return Response({"records": rows})

    def post(self, request):
        _staff(request)
        name = (request.data.get("company_name") or "").strip()
        sector = (request.data.get("sector") or "").strip()
        profile = (request.data.get("deployment_profile") or "saas").strip()
        notes = (request.data.get("notes") or "").strip()[:500]
        if not (2 <= len(name) <= 120):
            raise ValidationError("company_name must be 2-120 characters")
        if sector not in SECTORS:
            raise ValidationError("sector must be one of %s" % SECTORS)
        if profile not in DEPLOYMENT_PROFILES:
            raise ValidationError("deployment_profile must be one of %s"
                                  % DEPLOYMENT_PROFILES)

        slug = _slugify(name)
        tenant_id = str(uuid.uuid4())

        def create(cur):
            cur.execute(
                "INSERT INTO tenants (tenant_id, slug, name, status)"
                " VALUES (%s, %s, %s, 'onboarding')",
                [tenant_id, slug, name])
            cur.execute(
                "INSERT INTO onboarding_records (tenant_id, current_step,"
                " state, created_by) VALUES (%s, 'legal', %s, %s)",
                [tenant_id, json.dumps({
                    "company_name": name, "sector": sector,
                    "deployment_profile": profile, "notes": notes,
                }), request.user.email])
            _ledger_append(tenant_id, request.user.email,
                           "onboarding.started",
                           {"company_name": name, "sector": sector,
                            "deployment_profile": profile})

        try:
            _as_tenant(tenant_id, create)
        except Exception as exc:
            raise ValidationError(
                "could not start onboarding: %s" % exc) from exc

        return Response({"tenant_id": tenant_id, "slug": slug,
                         "current_step": "legal"}, status=status.HTTP_201_CREATED)


class _StepView(APIView):
    def post(self, request, tenant_id):
        _staff(request)
        rec = _record(tenant_id)
        if rec is None:
            return Response({"detail": "no onboarding record"},
                            status=status.HTTP_404_NOT_FOUND)
        if rec["status"] != "in_progress":
            raise ValidationError("onboarding is %s" % rec["status"])
        return self.step(request, rec)


class OnboardingLegalView(_StepView):
    """All required docs accepted or nothing: partial acceptance is not a
    state the platform will record."""

    def step(self, request, rec):
        tid = str(rec["tenant_id"])
        accepted = request.data.get("accepted") or {}
        acceptor = {
            "name": (request.data.get("acceptor_name") or "").strip()[:120],
            "email": (request.data.get("acceptor_email") or "").strip()[:120],
            "role": (request.data.get("acceptor_role") or "").strip()[:120],
        }
        if not acceptor["name"] or "@" not in acceptor["email"]:
            raise ValidationError("acceptor name and valid email required")

        for doc in LEGAL_DOCS.values():
            if doc["required"] and not accepted.get(doc["id"]):
                raise ValidationError(
                    "%s (%s) must be accepted" % (doc["title"], doc["version"]))

        legal = {doc["id"]: {
            "version": doc["version"],
            "accepted_by": acceptor["email"],
            "accepted_at_iso": datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"),
        } for doc in LEGAL_DOCS.values()}

        def write(cur):
            _ledger_append(tid, request.user.email, "onboarding.legal_accepted",
                           {"acceptor": acceptor, "documents": legal})

        _as_tenant(tid, write)
        _update_record(tid, legal=json.dumps(legal), current_step="admin")
        return Response({"legal": legal, "current_step": "admin"})


class OnboardingAdminView(_StepView):
    def step(self, request, rec):
        tid = str(rec["tenant_id"])
        if not rec["legal"]:
            raise ValidationError("legal step must complete first")

        email = (request.data.get("email") or "").strip().lower()
        name = (request.data.get("name") or "").strip()[:120]
        if "@" not in email:
            raise ValidationError("valid admin email required")

        from accounts.models import Membership, User
        if User.objects.filter(email=email).exists():
            raise ValidationError("a user with this email already exists")

        password = "Truvo-%s" % uuid.uuid4().hex[:12]
        created = {}

        def write(cur):
            # user + membership + ledger entry in ONE transaction: a partial
            # admin provisioning must not exist
            user = User.objects.create_user(
                username=email, email=email, password=password,
                first_name=name)
            Membership.objects.create(user=user, tenant_id=tid, role="admin",
                                      is_default=True)
            _ledger_append(tid, request.user.email, "onboarding.admin_created",
                           {"admin_email": email, "admin_name": name,
                            "role": "admin"})
            created["user"] = user

        _as_tenant(tid, write)
        _update_record(tid, current_step="environment",
                       state=json.dumps({**rec["state"], "admin": {
                           "email": email, "name": name}}))
        # password is returned ONCE — shown in the wizard, never stored
        return Response({"admin": {"email": email, "name": name},
                         "initial_password": password,
                         "current_step": "environment"})


class OnboardingEnvironmentView(_StepView):
    def step(self, request, rec):
        tid = str(rec["tenant_id"])
        if not rec["legal"]:
            raise ValidationError("legal step must complete first")

        sector = (request.data.get("sector")
                  or rec["state"].get("sector") or "").strip()
        if sector not in SECTORS:
            raise ValidationError("sector must be one of %s" % SECTORS)

        assets = request.data.get("assets") or []
        domains = request.data.get("watch_domains") or []
        idp = request.data.get("idp") or {}

        clean_assets = []
        for a in assets[:100]:
            cpe = (a.get("cpe") or "").strip()
            m = _CPE_RE.match(cpe)
            if not m:
                raise ValidationError("bad CPE: %r (expected cpe:2.3:a:vendor:product)" % cpe)
            try:
                count = max(1, min(int(a.get("count", 1)), 100000))
            except (TypeError, ValueError) as exc:
                raise ValidationError("bad asset count for %r" % cpe) from exc
            clean_assets.append((cpe, m.group("ven"), m.group("pro"), count))

        clean_domains = []
        for d in domains[:50]:
            dom = (d or "").strip().lower()
            if not _DOMAIN_RE.match(dom):
                raise ValidationError("bad domain: %r" % dom)
            clean_domains.append(dom)

        if idp.get("provider") not in (None, "", "entra", "okta"):
            raise ValidationError("idp.provider must be entra or okta")

        def write(cur):
            cur.execute(
                "INSERT INTO tenant_sector (tenant_id, sector) VALUES (%s,%s)"
                " ON CONFLICT (tenant_id) DO UPDATE SET sector = EXCLUDED.sector",
                [tid, sector])
            for cpe, ven, pro, count in clean_assets:
                cur.execute(
                    "INSERT INTO tenant_assets (tenant_id, cpe, vendor,"
                    " product, count) VALUES (%s,%s,%s,%s,%s)"
                    " ON CONFLICT (tenant_id, cpe) DO UPDATE SET count ="
                    " EXCLUDED.count", [tid, cpe, ven, pro, count])
            for dom in clean_domains:
                cur.execute(
                    "INSERT INTO tenant_domains (tenant_id, domain)"
                    " VALUES (%s,%s) ON CONFLICT DO NOTHING", [tid, dom])
            _ledger_append(tid, request.user.email,
                           "onboarding.environment_registered", {
                               "sector": sector,
                               "assets": len(clean_assets),
                               "watch_domains": len(clean_domains),
                               "idp": idp.get("provider") or "deferred",
                           })

        _as_tenant(tid, write)
        state = {**rec["state"], "sector": sector,
                 "idp": idp, "assets_registered": len(clean_assets),
                 "domains_registered": len(clean_domains)}
        _update_record(tid, state=json.dumps(state), current_step="review")
        return Response({"assets": len(clean_assets),
                         "watch_domains": len(clean_domains),
                         "current_step": "review"})


class OnboardingCompleteView(_StepView):
    def step(self, request, rec):
        tid = str(rec["tenant_id"])
        if not rec["legal"]:
            raise ValidationError("legal step must complete first")
        has_admin = "admin" in rec["state"]
        has_env = "sector" in rec["state"]
        if not (has_admin and has_env):
            raise ValidationError(
                "admin and environment steps must complete first")

        def write(cur):
            cur.execute("UPDATE tenants SET status = 'active'"
                        " WHERE tenant_id = %s", [tid])
            _ledger_append(tid, request.user.email, "tenant.activated", {
                "company_name": rec["state"].get("company_name"),
                "sector": rec["state"].get("sector"),
                "deployment_profile": rec["state"].get("deployment_profile"),
                "legal_documents": {
                    k: v["version"] for k, v in rec["legal"].items()},
                "admin": rec["state"].get("admin"),
            })

        _as_tenant(tid, write)
        _update_record(tid, status="completed", current_step="review",
                       completed_at=datetime.now(timezone.utc).strftime(
                           "%Y-%m-%dT%H:%M:%SZ"))
        return Response({"tenant_id": tid, "status": "active"})


class OnboardingDetailView(APIView):
    def get(self, request, tenant_id):
        _staff(request)
        rec = _record(tenant_id)
        if rec is None:
            return Response({"detail": "no onboarding record"},
                            status=status.HTTP_404_NOT_FOUND)
        return Response(rec)

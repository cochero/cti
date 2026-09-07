"""MIS API v1 — the analyst console + CISO dashboard read/act surface.

Every read here is tenant-fenced by Postgres RLS (the request connection
carries truvo.tenant_id from TenantContextMiddleware — the fence is the
database, not this code). Writes are exactly one kind: rule lifecycle
transitions (staged -> active/rejected), which are analyst work by
definition, RBAC-gated, and land on the tenant's hash-chained ledger so
every release decision is auditable years later (Architecture §1.4, §8).

Rule generation stays in detection-factory (a service API, indicator
input required); this surface governs REVIEW and RELEASE — the human gate.
"""

import json
import uuid

from rest_framework import status
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView
from truvo_core.hashchain import LedgerEntry, append_entry

from .api import RequireMembership


def _rows(sql, params=None):
    from django.db import connection
    with connection.cursor() as cur:
        cur.execute(sql, params or [])
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, row, strict=False)) for row in cur.fetchall()]


def _ledger_append(tenant_id, actor, kind, payload):
    """Append a hash-chained entry on the request tenant's ledger — same
    discipline as scoring-svc: per-tenant advisory lock, chain from head.
    The connection already carries tenant context (RLS fences the read)."""
    from django.db import connection
    with connection.cursor() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(hashtext('ledger:' || %s))",
                    [tenant_id])
        cur.execute(
            "SELECT seq, ts_iso, actor, kind, payload, prev_hash, entry_hash"
            " FROM ledger_entries WHERE tenant_id = %s ORDER BY seq DESC LIMIT 1",
            [tenant_id],
        )
        row = cur.fetchone()
        prev = LedgerEntry(seq=row[0], ts_iso=row[1], tenant=tenant_id,
                           actor=row[2], kind=row[3], payload=row[4],
                           prev_hash=row[5], entry_hash=row[6]) if row else None
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        entry = append_entry(prev, ts_iso=ts, tenant=tenant_id, actor=actor,
                             kind=kind, payload=payload)
        cur.execute(
            "INSERT INTO ledger_entries (tenant_id, seq, ts_iso, actor, kind,"
            " payload, prev_hash, entry_hash) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
            [tenant_id, entry.seq, entry.ts_iso, entry.actor, entry.kind,
             json.dumps(entry.payload), entry.prev_hash, entry.entry_hash],
        )
        return entry.seq


class PrioritiesView(RequireMembership, APIView):
    """The PRIORITIZE queue: latest score per CVE, joined with the exploit
    intel that fed it. RLS fences scores to the caller's tenant."""

    def get(self, request):
        self.check_membership(request)
        limit = min(int(request.query_params.get("limit", "50")), 500)
        min_priority = int(request.query_params.get("min_priority", "0"))
        rows = _rows(
            """
            SELECT s.cve, s.priority_millis, s.scored_at, s.weights_version,
                   s.ledger_seq,
                   ei.kev, ei.epss_millis, ei.cvss_millis, ei.poc_public,
                   (SELECT count(*) FROM detection_rules r
                     WHERE r.tenant_id = s.tenant_id AND r.cve = s.cve
                       AND r.status = 'active') AS active_rules
              FROM (SELECT DISTINCT ON (cve) cve, priority_millis, scored_at,
                           weights_version, ledger_seq, tenant_id
                      FROM scores ORDER BY cve, scored_at DESC) s
              LEFT JOIN exploit_intel ei ON ei.cve = s.cve
             WHERE s.priority_millis >= %s
             ORDER BY s.priority_millis DESC, s.cve
             LIMIT %s
            """,
            [min_priority, limit],
        )
        return Response({"priorities": rows, "count": len(rows)})


class PriorityDecompositionView(RequireMembership, APIView):
    """The audit drill-down: the full factor decomposition for one score,
    served from the ledger entry that recorded it (replayable by design)."""

    def get(self, request, cve):
        self.check_membership(request)
        rows = _rows(
            """
            SELECT seq, ts_iso, actor, payload
              FROM ledger_entries
             WHERE kind = 'score.emitted' AND payload->>'cve' = %s
             ORDER BY seq DESC LIMIT 1
            """,
            [cve],
        )
        if not rows:
            return Response({"detail": "no scored entry for %s" % cve},
                            status=status.HTTP_404_NOT_FOUND)
        row = rows[0]
        # jsonb parses to dict under psycopg2 and raw psycopg3, but Django's
        # psycopg3 adapter returns str — normalize so the console contract
        # is always an object.
        payload = row["payload"]
        if isinstance(payload, str):
            payload = json.loads(payload)
        return Response({
            "cve": cve,
            "ledger_seq": row["seq"],
            "scored_at": row["ts_iso"],
            "scored_by": row["actor"],
            "decomposition": payload,
        })


class RulesView(RequireMembership, APIView):
    """Detection content for review: the HUNT output. Staged rules await
    analyst verdict; content is returned in full (it is what ships)."""

    def get(self, request):
        self.check_membership(request)
        status_filter = request.query_params.get("status")
        params = []
        sql = """
            SELECT rule_id, cve, format, title, content, content_sha256,
                   signature, status, fp_estimate_millis, generator_version,
                   created_at, activated_at
              FROM detection_rules
            """
        if status_filter:
            sql += " WHERE status = %s"
            params.append(status_filter)
        sql += " ORDER BY created_at DESC LIMIT 500"
        rows = _rows(sql, params)
        return Response({"rules": rows, "count": len(rows)})


#: legal state machine for the human gate (T3: nothing auto-deploys)
_RULE_TRANSITIONS = {
    "activate": {"from": "staged", "to": "active"},
    "reject": {"from": "staged", "to": "rejected"},
    "supersede": {"from": "active", "to": "superseded"},
}


class RuleTransitionView(RequireMembership, APIView):
    """The release gate: staged -> active is the moment content becomes
    deployable, so it is analyst/admin-only and ledger-recorded. The
    transition map is code, not configuration — a rejected rule cannot be
    resurrected from this surface (audit trail stays monotone)."""

    def post(self, request, rule_id):
        self.check_membership(request)
        role = request.membership.role
        if role not in ("admin", "analyst"):
            raise PermissionDenied("role %r may not release rules" % role)

        action = request.data.get("action")
        if action not in _RULE_TRANSITIONS:
            raise ValidationError("action must be one of %s"
                                  % sorted(_RULE_TRANSITIONS))
        try:
            uuid.UUID(str(rule_id))
        except (ValueError, AttributeError) as exc:
            raise ValidationError("rule_id must be a UUID") from exc

        transition = _RULE_TRANSITIONS[action]
        rows = _rows(
            "SELECT rule_id, status, title, cve, content_sha256 FROM"
            " detection_rules WHERE rule_id = %s", [str(rule_id)],
        )
        if not rows:
            return Response({"detail": "unknown rule"}, status=status.HTTP_404_NOT_FOUND)
        rule = rows[0]
        if rule["status"] != transition["from"]:
            raise ValidationError(
                "rule is %r; %s requires %r" % (rule["status"], action,
                                                transition["from"]))

        from django.db import connection
        with connection.cursor() as cur:
            cur.execute(
                "UPDATE detection_rules SET status = %s, activated_at ="
                " CASE WHEN %s = 'active' THEN now() ELSE activated_at END"
                " WHERE rule_id = %s AND status = %s",
                [transition["to"], transition["to"], str(rule_id),
                 transition["from"]],
            )
            updated = cur.rowcount
        if not updated:  # lost a race with another reviewer
            raise ValidationError("rule state changed; reload and retry")

        seq = _ledger_append(
            request.tenant_id, request.user.email, "rule.%s" % transition["to"],
            {
                "rule_id": str(rule_id), "title": rule["title"],
                "cve": rule["cve"], "content_sha256": rule["content_sha256"],
                "from": rule["status"], "action": action,
            },
        )
        return Response({"rule_id": str(rule_id),
                         "status": transition["to"], "ledger_seq": seq})


class AttackHeatmapView(RequireMembership, APIView):
    """ATT&CK technique activity from corroborated pipeline claims (global
    threat landscape, last 90 days). Tenant-relative coloring arrives with
    per-tenant graph depth; v0 shows what the world is doing."""

    def get(self, request):
        self.check_membership(request)
        rows = _rows(
            """
            SELECT t AS technique_id, count(*) AS claim_count,
                   max(ingested_at) AS last_seen
              FROM claims, unnest(attack_technique_ids) AS t
             WHERE ingested_at > now() - interval '90 days'
             GROUP BY t ORDER BY claim_count DESC, t LIMIT 1000
            """
        )
        return Response({"techniques": rows, "count": len(rows)})


class DashboardSummaryView(RequireMembership, APIView):
    """CISO view: posture aggregates over the tenant's RLS-fenced data."""

    def get(self, request):
        self.check_membership(request)
        top = _rows(
            """
            SELECT s.cve, s.priority_millis, ei.kev
              FROM (SELECT DISTINCT ON (cve) cve, priority_millis
                      FROM scores ORDER BY cve, scored_at DESC) s
              LEFT JOIN exploit_intel ei ON ei.cve = s.cve
             ORDER BY s.priority_millis DESC LIMIT 5
            """
        )
        rules = {r["status"]: r["n"] for r in _rows(
            "SELECT status, count(*) AS n FROM detection_rules GROUP BY status"
        )}
        assets = _rows(
            "SELECT count(*) AS products, coalesce(sum(count),0) AS instances"
            " FROM tenant_assets")
        identities = _rows(
            "SELECT count(*) AS total,"
            " count(*) FILTER (WHERE privileged) AS privileged FROM identities")
        scored = _rows(
            "SELECT count(DISTINCT cve) AS cves FROM scores")
        kev_top = sum(1 for t in top if t["kev"])
        return Response({
            "top_priorities": top,
            "kev_in_top": kev_top,
            "rules_by_status": {
                "staged": rules.get("staged", 0),
                "active": rules.get("active", 0),
                "rejected": rules.get("rejected", 0),
                "superseded": rules.get("superseded", 0),
            },
            "assets": assets[0] if assets else {"products": 0, "instances": 0},
            "identities": identities[0] if identities else
                          {"total": 0, "privileged": 0},
            "scored_cves": scored[0]["cves"] if scored else 0,
        })


def _with_csrf_cookie(request, response):
    """Manually attach a fresh csrftoken cookie.

    DRF marks APIViews csrf_exempt, which suppresses not only request
    validation but also CsrfViewMiddleware's response cookie emission —
    so a session established through an APIView would otherwise leave the
    SPA with no token for its next authenticated POST. Setting the cookie
    here keeps the whole flow inside the view.
    """
    from django.conf import settings as dj_settings
    from django.middleware.csrf import get_token
    response.set_cookie(
        dj_settings.CSRF_COOKIE_NAME,
        get_token(request),
        samesite="Lax",
        secure=dj_settings.SESSION_COOKIE_SECURE,
    )
    return response


class LoginView(APIView):
    """Session login for the SPA. In SSO deployments OIDC sits in front
    (mozilla_django_oidc) and this endpoint is simply unused — it exists
    so the console works in dev, self-hosted, and air-gap profiles where
    an IdP may not be reachable. Rate limiting arrives with the gateway."""

    authentication_classes = []  # the request IS the credentials
    permission_classes = []

    def post(self, request):
        from django.contrib.auth import authenticate, login
        email = (request.data.get("email") or "").strip()
        password = request.data.get("password") or ""
        user = authenticate(request, username=email, password=password)
        if user is None:
            return Response({"detail": "invalid credentials"},
                            status=status.HTTP_401_UNAUTHORIZED)
        login(request, user)  # rotates the session AND the csrf token
        membership = (user.memberships.filter(is_default=True).first()
                      or user.memberships.first())
        return _with_csrf_cookie(request, Response({
            "user": user.email,
            "tenant_id": str(membership.tenant_id) if membership else None,
            "role": membership.role if membership else None,
        }))


class LogoutView(APIView):
    def post(self, request):
        from django.contrib.auth import logout
        logout(request)
        return _with_csrf_cookie(request, Response({"detail": "logged out"}))

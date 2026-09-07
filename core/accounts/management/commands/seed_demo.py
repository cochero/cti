"""Seed the demo tenant: a finance-sector shop with a real attack surface.

Creates (idempotently):
  - tenant `demo` (sector: finance) + demo users (analyst, viewer)
  - tenant assets (CPEs) for products hit by well-known KEV CVEs
  - graph edges linking those CPEs to the CVEs that exploit them, plus a
    threat-actor path so actor_reach and sector_affinity have signal
  - a small identity directory so identity_exposure has a denominator

Run AFTER the intelligence pipeline has enriched exploit_intel (collect ->
extract -> corroborate -> enrich) so scoring finds the KEV/EPSS signals;
assets and wiring are added regardless and light up once intel lands.

    python manage.py seed_demo

Users: demo-analyst@truvo.local / demo-pass (analyst)
       demo-viewer@truvo.local  / demo-pass (viewer)
"""

import uuid

from accounts.models import Membership, User
from django.core.management.base import BaseCommand
from tenancy.models import Tenant

PASSWORD = "demo-pass"

# Real (CVE, CPE) pairs — every CVE is CISA KEV-listed, every CPE canonical.
PAIRS = [
    ("CVE-2023-49105", "cpe:2.3:a:owncloud:core", 4),
    ("CVE-2024-21762", "cpe:2.3:o:fortinet:fortios", 12),
    ("CVE-2023-22527", "cpe:2.3:a:atlassian:confluence_data_center", 3),
    ("CVE-2023-46805", "cpe:2.3:a:ivanti:connect_secure", 6),
    ("CVE-2021-44228", "cpe:2.3:a:apache:log4j", 30),
]


class Command(BaseCommand):
    help = "Seed the demo tenant with assets, users, and graph wiring"

    def handle(self, *args, **options):
        from django.db import connection

        tenant = Tenant.objects.filter(slug="demo").first()
        if tenant is None:
            with connection.cursor() as cur:
                cur.execute(
                    "INSERT INTO tenants (tenant_id, slug, name, status)"
                    " VALUES (%s, 'demo', 'Demo Financial Services', 'active')"
                    " RETURNING tenant_id", [str(uuid.uuid4())],
                )
                tid = str(cur.fetchone()[0])
        else:
            tid = str(tenant.tenant_id)
        self.stdout.write("tenant demo = %s" % tid)

        with connection.cursor() as cur:
            cur.execute("SELECT cve FROM exploit_intel")
            known = {r[0] for r in cur.fetchall()}
            if not known:
                self.stdout.write(self.style.WARNING(
                    "exploit_intel is empty — run the pipeline + enrich to "
                    "light up KEV/EPSS signals for these assets"))

            cur.execute(
                "INSERT INTO tenant_sector (tenant_id, sector)"
                " VALUES (%s, 'finance')"
                " ON CONFLICT (tenant_id) DO NOTHING", [tid])

            for cve, cpe, count in PAIRS:
                if cve not in known:
                    self.stdout.write(self.style.WARNING(
                        "  %s not in exploit_intel yet" % cve))
                cur.execute(
                    "INSERT INTO tenant_assets (tenant_id, cpe, vendor,"
                    " product, count) VALUES (%s, %s, %s, %s, %s)"
                    " ON CONFLICT (tenant_id, cpe) DO NOTHING",
                    [tid, cpe, cpe.split(":")[3], cpe.split(":")[4], count],
                )
                cur.execute(
                    "INSERT INTO graph_edges (src_type, src_id, rel,"
                    " dst_type, dst_id)"
                    " VALUES ('INFRASTRUCTURE', %s, 'exploits', 'CVE', %s)"
                    " ON CONFLICT DO NOTHING", [cpe, cve],
                )

            # actor path: Lazarus uses malware that exploits the log4j RCE,
            # and targets the finance sector (both real-world properties)
            cur.execute(
                "INSERT INTO graph_edges (src_type, src_id, rel, dst_type,"
                " dst_id) VALUES"
                " ('THREAT_ACTOR','Lazarus Group','uses','MALWARE','Andariel'),"
                " ('MALWARE','Andariel','exploits','CVE','CVE-2021-44228'),"
                " ('THREAT_ACTOR','Lazarus Group','targets','SECTOR','finance')"
                " ON CONFLICT DO NOTHING")

            cur.execute("SELECT count(*) FROM identities")
            if cur.fetchone()[0] == 0:
                cur.execute(
                    "INSERT INTO identities (tenant_id, source, principal_id,"
                    " kind, display, privileged, roles)"
                    " VALUES"
                    " (%s, 'entra', 'dadeyemi@demo.local', 'user',"
                    "  'D. Adeyemi', true, ARRAY['Global Admin']),"
                    " (%s, 'entra', 'schen@demo.local', 'user',"
                    "  'S. Chen', false, '{}'),"
                    " (%s, 'entra', 'svc-jira@demo.local', 'service',"
                    "  'Ops Service Acct', true, ARRAY['Application Admin']),"
                    " (%s, 'okta', 'mrossi@demo.local', 'user',"
                    "  'M. Rossi', false, '{}')",
                    [tid, tid, tid, tid])

        analyst, _ = User.objects.get_or_create(
            email="demo-analyst@truvo.local",
            defaults={"username": "demo-analyst"})
        analyst.set_password(PASSWORD)
        analyst.is_staff = True
        analyst.save()
        viewer, _ = User.objects.get_or_create(
            email="demo-viewer@truvo.local", defaults={"username": "demo-viewer"})
        viewer.set_password(PASSWORD)
        viewer.save()
        Membership.objects.get_or_create(
            user=analyst, tenant_id=tid,
            defaults={"role": "analyst", "is_default": True})
        Membership.objects.get_or_create(
            user=viewer, tenant_id=tid,
            defaults={"role": "viewer", "is_default": True})

        self.stdout.write(self.style.SUCCESS(
            "demo world seeded: %d assets, identities, users"
            " demo-analyst@truvo.local + demo-viewer@truvo.local"
            " (password %r)" % (len(PAIRS), PASSWORD)))

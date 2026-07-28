# TRUVO on a VPS — production bring-up

Single-VPS deployment: data stores + all services + Django core + Caddy TLS,
in one `docker compose`. This is the recommended first live environment
(before Kubernetes). Live-validated build; treat as staging-grade until the
hardening checklist at the bottom is done.

## 0. What you need
- A VPS: **16 GB RAM, 4 vCPU, 100 GB SSD** minimum (32/8/200 comfortable).
  Hetzner CCX / DigitalOcean / Linode. Ubuntu 24.04 LTS.
- A **domain** with a DNS **A-record** pointing at the VPS IP.
- SSH access (key-only).

## 1. Prepare the VPS
```bash
# as root on the fresh VPS
apt-get update && apt-get install -y docker.io docker-compose-v2 git openssl
systemctl enable --now docker

# firewall: only SSH (from your IP) + HTTP/HTTPS. Data stores stay internal.
ufw default deny incoming && ufw default allow outgoing
ufw allow from YOUR.IP.ADDRESS to any port 22
ufw allow 80/tcp && ufw allow 443/tcp
ufw enable
```

## 2. Get the code + configure
```bash
git clone https://github.com/cochero/cti.git && cd cti/deploy/vps
cp .env.example .env
# edit .env: set TRUVO_DOMAIN to your domain. Leave the CHANGE_ME secrets —
# bootstrap.sh generates strong random values for them.
nano .env
```

## 3. Bootstrap (once) — real secrets, production vault, RLS role
```bash
chmod +x bootstrap.sh backup.sh
./bootstrap.sh
```
This generates secrets, **initializes + unseals OpenBao in production mode**
(save the printed unseal key + root token OFFLINE — shown once), runs the SQL
migrations, and sets the `truvo_app` role's real password.

## 4. Go live
```bash
docker compose -f docker-compose.prod.yml up -d --build
docker compose -f docker-compose.prod.yml ps      # all healthy?
```
Caddy fetches a Let's Encrypt cert automatically. Visit
`https://<your-domain>` — it routes to the Django core (SSO/RBAC/MIS).

Create the first admin:
```bash
docker compose -f docker-compose.prod.yml exec core python manage.py createsuperuser
```

## After a reboot / vault reseal
OpenBao seals on restart (by design). Unseal it, then bring services back:
```bash
docker compose -f docker-compose.prod.yml exec -e BAO_ADDR=http://127.0.0.1:8200 \
  openbao bao operator unseal <YOUR_UNSEAL_KEY>
docker compose -f docker-compose.prod.yml up -d
```
(Auto-unseal via cloud KMS is the production upgrade — ADR-0005.)

## Backups (set up day one)
```bash
# nightly cron: pg_dump -> object store (repoint at OFFSITE S3 for real prod)
echo "0 3 * * * $(pwd)/backup.sh >> $(pwd)/backup.log 2>&1" | crontab -
```

## Architecture notes
- **Only Caddy is exposed** (80/443). The FastAPI services have no auth of
  their own — they rely on network isolation + service-identity signing.
  Caddy routes ONLY to `core`; never expose the raw services (see Caddyfile).
- **Data stores have no host ports** — reachable only on the compose network.
- **Migrations** run as an ordered one-shot (`migrate` service) before
  services start; the content-hash-locked runner makes re-runs safe.

## Hardening checklist before REAL customer data
- [ ] OpenBao unseal via cloud KMS (not manual key), `-key-shares=5`
- [ ] Off-site encrypted backups (not the local MinIO)
- [ ] Real SSO/OIDC configured (Entra/Okta) — set `TRUVO_OIDC_*` in core env
- [ ] The unverified integrations tested live (Splunk/Sentinel, EntraProvider)
- [ ] Per-service THREAT_MODEL.md + runbook reviewed
- [ ] Fail2ban / SSH hardening; automatic security updates
- [ ] Understand scoring weights are UNCALIBRATED (fine for a knowing design partner)

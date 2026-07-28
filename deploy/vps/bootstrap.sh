#!/usr/bin/env bash
# TRUVO production bootstrap — run ONCE on a fresh VPS after `docker compose up -d`.
# Idempotent where it can be. Turns the dev-mode scaffolding into real prod:
#   1. generates strong secrets into .env (if still CHANGE_ME)
#   2. initializes + unseals OpenBao in PRODUCTION mode, captures root token
#   3. provisions the truvo_app RLS role's real password (post-migration)
#
# Prereqs: .env exists (cp .env.example .env) with TRUVO_DOMAIN set.
set -euo pipefail
cd "$(dirname "$0")"
COMPOSE="docker compose -f docker-compose.prod.yml"

if [ ! -f .env ]; then echo "cp .env.example .env and set TRUVO_DOMAIN first"; exit 1; fi

gen() { openssl rand -base64 32 | tr -d '/+=' | head -c 40; }

echo "== 1. fill secret blanks in .env =="
fill() {  # fill KEY if its value is still a CHANGE_ME placeholder
  local key="$1" val="$2"
  if grep -q "^${key}=CHANGE_ME" .env; then
    sed -i "s|^${key}=.*|${key}=${val}|" .env
    echo "   set ${key}"
  fi
}
APP_PW=$(gen)
fill POSTGRES_ADMIN_PASSWORD "$(gen)"
fill TRUVO_APP_DB_PASSWORD "$APP_PW"
fill MINIO_PASSWORD "$(gen)"
fill DJANGO_SECRET_KEY "$(openssl rand -base64 50 | tr -d '/+=' | head -c 50)"
# keep the app DB URL password in sync with TRUVO_APP_DB_PASSWORD
APP_PW_NOW=$(grep '^TRUVO_APP_DB_PASSWORD=' .env | cut -d= -f2)
sed -i "s|^TRUVO_APP_DB_URL=.*|TRUVO_APP_DB_URL=postgresql://truvo_app:${APP_PW_NOW}@postgres:5432/truvo|" .env

echo "== 2. initialize + unseal OpenBao (production mode) =="
$COMPOSE up -d openbao
sleep 5
if $COMPOSE exec -T openbao bao status 2>/dev/null | grep -q 'Initialized.*true'; then
  echo "   already initialized — skipping (unseal manually if sealed)"
else
  # 1 key share for simplicity; PRODUCTION should use -key-shares=5 -key-threshold=3
  INIT=$($COMPOSE exec -T -e BAO_ADDR=http://127.0.0.1:8200 openbao \
      bao operator init -key-shares=1 -key-threshold=1 -format=json)
  UNSEAL=$(echo "$INIT" | python3 -c 'import json,sys;print(json.load(sys.stdin)["unseal_keys_b64"][0])')
  ROOT=$(echo "$INIT"  | python3 -c 'import json,sys;print(json.load(sys.stdin)["root_token"])')
  $COMPOSE exec -T -e BAO_ADDR=http://127.0.0.1:8200 openbao bao operator unseal "$UNSEAL" >/dev/null
  $COMPOSE exec -T -e BAO_ADDR=http://127.0.0.1:8200 -e BAO_TOKEN="$ROOT" openbao \
      bao secrets enable -path=secret kv-v2 >/dev/null 2>&1 || true
  sed -i "s|^TRUVO_VAULT_TOKEN=.*|TRUVO_VAULT_TOKEN=${ROOT}|" .env
  echo ""
  echo "   >>> STORE THESE OFFLINE — they are shown once <<<"
  echo "   UNSEAL KEY: ${UNSEAL}"
  echo "   ROOT TOKEN: ${ROOT}"
  echo "   (root token written to .env; unseal key is NOT — save it now)"
  echo ""
fi

echo "== 3. start data stores + run migrations =="
$COMPOSE up -d postgres redpanda minio
sleep 8
$COMPOSE up migrate   # runs SQL migrations 0001..NNNN as admin, then exits

echo "== 4. provision the truvo_app RLS role password =="
source .env
$COMPOSE exec -T postgres psql -U truvo -d truvo \
    -c "ALTER ROLE truvo_app WITH PASSWORD '${TRUVO_APP_DB_PASSWORD}';"

echo ""
echo "== bootstrap done. Now: $COMPOSE up -d =="
echo "   Then visit https://$(grep ^TRUVO_DOMAIN= .env | cut -d= -f2)"

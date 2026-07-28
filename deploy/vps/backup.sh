#!/usr/bin/env bash
# Nightly Postgres backup to the object store (off-box in real prod: point
# BACKUP_DEST at external S3, not the local MinIO). The ledger + scores are
# the crown jewels — this is not optional.
set -euo pipefail
cd "$(dirname "$0")"
source .env
TS=$(date -u +%Y%m%dT%H%M%SZ)
FILE="truvo-pg-${TS}.sql.gz"

docker compose -f docker-compose.prod.yml exec -T postgres     pg_dump -U truvo truvo | gzip > "/tmp/${FILE}"

# upload to MinIO (replace with external S3 / offsite in production)
docker compose -f docker-compose.prod.yml exec -T minio     sh -c "mc alias set local http://localhost:9000 ${MINIO_USER} ${MINIO_PASSWORD} >/dev/null 2>&1;            mc mb -p local/truvo-backups >/dev/null 2>&1 || true"
docker compose -f docker-compose.prod.yml cp "/tmp/${FILE}" minio:/tmp/${FILE}
docker compose -f docker-compose.prod.yml exec -T minio     mc cp /tmp/${FILE} local/truvo-backups/${FILE}
rm -f "/tmp/${FILE}"
echo "backed up: truvo-backups/${FILE}"

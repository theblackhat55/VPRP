#!/bin/bash
# ============================================================
# VPRP Database Backup Script
# Usage: bash scripts/backup.sh
# Cron:  0 2 * * * cd /home/vprp/VPRP && bash scripts/backup.sh >> ~/vprp-data/logs/backup.log 2>&1
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(dirname "$SCRIPT_DIR")"
BACKUP_DIR="$HOME/vprp-data/backups"
RETENTION_DAYS=30
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/vprp_db_${TIMESTAMP}.dump"

cd "$APP_DIR"

# Source .env for credentials
if [ ! -f ".env" ]; then
    echo "[$(date)] ERROR: .env file not found at ${APP_DIR}/.env"
    exit 1
fi

set -a
source .env
set +a

# Check if postgres is running
if ! docker compose ps postgres --status running -q > /dev/null 2>&1; then
    echo "[$(date)] ERROR: PostgreSQL container is not running"
    exit 1
fi

echo "[$(date)] Starting database backup..."

docker compose exec -T postgres pg_dump \
    -U "${POSTGRES_USER:-vprp_user}" \
    -d "${POSTGRES_DB:-vprp}" \
    --format=custom \
    --compress=9 \
    > "$BACKUP_FILE"

BACKUP_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
echo "[$(date)] Backup complete: ${BACKUP_FILE} (${BACKUP_SIZE})"

# Cleanup old backups
echo "[$(date)] Removing backups older than ${RETENTION_DAYS} days..."
find "$BACKUP_DIR" -name "vprp_db_*.dump" -mtime +${RETENTION_DAYS} -delete

REMAINING=$(find "$BACKUP_DIR" -name "vprp_db_*.dump" 2>/dev/null | wc -l)
echo "[$(date)] Done. ${REMAINING} backup(s) retained."

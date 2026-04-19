#!/bin/bash
# ============================================================
# VPRP Database Restore Script
# Usage: bash scripts/restore.sh [backup_file]
#        No argument = restore from latest backup
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(dirname "$SCRIPT_DIR")"
BACKUP_DIR="$HOME/vprp-data/backups"
BACKUP_FILE="${1:-}"

cd "$APP_DIR"

if [ ! -f ".env" ]; then
    echo "ERROR: .env file not found"
    exit 1
fi

set -a
source .env
set +a

# Find backup file
if [ -z "$BACKUP_FILE" ]; then
    BACKUP_FILE=$(find "$BACKUP_DIR" -name "vprp_db_*.dump" -print0 2>/dev/null | \
        xargs -0 ls -t 2>/dev/null | head -1)
    if [ -z "$BACKUP_FILE" ]; then
        echo "ERROR: No backup files found in ${BACKUP_DIR}"
        exit 1
    fi
fi

if [ ! -f "$BACKUP_FILE" ]; then
    echo "ERROR: Backup file not found: ${BACKUP_FILE}"
    exit 1
fi

echo "============================================="
echo "  VPRP Database Restore"
echo "  Source: ${BACKUP_FILE}"
echo "============================================="
echo ""
read -p "WARNING: This will OVERWRITE the current database. Continue? (yes/no): " confirm
if [ "$confirm" != "yes" ]; then
    echo "Aborted."
    exit 0
fi

echo "[$(date)] Stopping application..."
docker compose stop app

echo "[$(date)] Restoring database..."
docker compose exec -T postgres pg_restore \
    -U "${POSTGRES_USER:-vprp_user}" \
    -d "${POSTGRES_DB:-vprp}" \
    --clean --if-exists \
    < "$BACKUP_FILE"

echo "[$(date)] Starting application..."
docker compose start app

echo "[$(date)] Restore complete."

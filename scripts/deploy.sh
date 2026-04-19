#!/bin/bash
# ============================================================
# VPRP Production Deployment Script
# Usage: bash scripts/deploy.sh [git-ref]
#        bash scripts/deploy.sh           # deploys main
#        bash scripts/deploy.sh v1.0.0    # deploys a tag
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(dirname "$SCRIPT_DIR")"
BACKUP_DIR="$HOME/vprp-data/backups"
GIT_REF="${1:-main}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "============================================="
echo "  VPRP Production Deployment"
echo "  $(date)"
echo "  Target: ${GIT_REF}"
echo "============================================="

cd "$APP_DIR"

# 1. Pre-flight
echo ""
echo "[1/6] Pre-flight checks..."
if [ ! -f ".env" ]; then
    echo "  ERROR: .env file not found."
    exit 1
fi
echo "  .env found"

# 2. Backup database (if running)
echo ""
echo "[2/6] Backing up database..."
if docker compose ps postgres --status running -q > /dev/null 2>&1; then
    set -a && source .env && set +a
    docker compose exec -T postgres pg_dump \
        -U "${POSTGRES_USER:-vprp_user}" \
        -d "${POSTGRES_DB:-vprp}" \
        --format=custom \
        > "${BACKUP_DIR}/pre_deploy_${TIMESTAMP}.dump" 2>/dev/null \
        && echo "  Backup saved" \
        || echo "  Backup skipped (empty database)"
else
    echo "  Skipping — database not running"
fi

# 3. Pull latest code
echo ""
echo "[3/6] Pulling code..."
git fetch --all --tags
git checkout "$GIT_REF"
if [ "$GIT_REF" = "main" ]; then
    git pull origin main
fi
CURRENT_COMMIT=$(git rev-parse --short HEAD)
echo "  Now at: ${CURRENT_COMMIT}"

# 4. Build and restart
echo ""
echo "[4/6] Building and restarting..."
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build

# 5. Health check
echo ""
echo "[5/6] Waiting for health..."
RETRIES=0
MAX_RETRIES=30
until curl -sf http://localhost:8501/_stcore/health > /dev/null 2>&1; do
    RETRIES=$((RETRIES + 1))
    if [ $RETRIES -ge $MAX_RETRIES ]; then
        echo "  ERROR: App failed to start after ${MAX_RETRIES} attempts"
        echo "  Check logs: docker compose logs app"
        exit 1
    fi
    printf "  Waiting... (%d/%d)\r" "$RETRIES" "$MAX_RETRIES"
    sleep 5
done
echo "  Healthy!                    "

# 6. Cleanup
echo ""
echo "[6/6] Cleaning up old images..."
docker image prune -f > /dev/null 2>&1

echo ""
echo "============================================="
echo "  Deployment complete!"
echo "  Commit: ${CURRENT_COMMIT}"
echo "============================================="
docker compose -f docker-compose.yml -f docker-compose.prod.yml ps

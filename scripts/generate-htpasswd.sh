#!/bin/bash
# ============================================================
# Generate htpasswd file for Nginx basic auth
# Usage: bash scripts/generate-htpasswd.sh
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(dirname "$SCRIPT_DIR")"
HTPASSWD_FILE="${APP_DIR}/nginx/htpasswd"

echo "VPRP — Generate Nginx Basic Auth Credentials"
echo "============================================="
echo ""

if [ -f "$HTPASSWD_FILE" ]; then
    echo "Existing htpasswd file found. Adding/updating user."
    read -p "Username: " username
    htpasswd -B "$HTPASSWD_FILE" "$username"
else
    read -p "Username: " username
    htpasswd -B -c "$HTPASSWD_FILE" "$username"
fi

echo ""
echo "Credentials saved to ${HTPASSWD_FILE}"
echo "Note: this file is in .gitignore — create it on each server."

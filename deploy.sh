#!/usr/bin/env bash
###############################################################################
# VPRP – Vulnerability Prioritization & Remediation Platform
# Interactive Deployment Script v1.2
#
# Usage:
#   chmod +x deploy.sh && ./deploy.sh
#
# Features:
#   - Auto-detects Caddy and uses it instead of nginx
#   - Smart directory detection (never creates nested clones)
#   - Handles port conflicts automatically
#   - Creates admin user and runs migrations
###############################################################################
set -uo pipefail

# ─── Colors & helpers ────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

banner() {
  clear
  echo ""
  echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${CYAN}${BOLD}║                                                                  ║${NC}"
  echo -e "${CYAN}${BOLD}║     🛡️  VPRP – Vulnerability Prioritization & Remediation        ║${NC}"
  echo -e "${CYAN}${BOLD}║                    Deployment Script v1.2                        ║${NC}"
  echo -e "${CYAN}${BOLD}║                                                                  ║${NC}"
  echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════════════╝${NC}"
  echo ""
}

info()    { echo -e "  ${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "  ${GREEN}[  OK]${NC}  $*"; }
warn()    { echo -e "  ${YELLOW}[WARN]${NC}  $*"; }
fail()    { echo -e "  ${RED}[FAIL]${NC}  $*"; }

step() {
  echo ""
  echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${BOLD}  Step $1 ▸ $2${NC}"
  echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

ask() {
  local var="$1" prompt="$2" default="${3:-}"
  if [[ -n "$default" ]]; then
    read -rp "$(echo -e "  ${CYAN}?${NC} ${prompt} [${default}]: ")" val
    val="${val:-$default}"
  else
    read -rp "$(echo -e "  ${CYAN}?${NC} ${prompt}: ")" val
  fi
  eval "$var=\"\$val\""
}

ask_secret() {
  local var="$1" prompt="$2" default="${3:-}"
  if [[ -n "$default" ]]; then
    read -srp "$(echo -e "  ${CYAN}?${NC} ${prompt} [auto-generated]: ")" val
    echo ""
    val="${val:-$default}"
  else
    read -srp "$(echo -e "  ${CYAN}?${NC} ${prompt}: ")" val
    echo ""
  fi
  eval "$var=\"\$val\""
}

ask_yn() {
  local prompt="$1" default="${2:-y}"
  local yn
  read -rp "$(echo -e "  ${CYAN}?${NC} ${prompt} [${default}]: ")" yn
  yn="${yn:-$default}"
  [[ "$yn" =~ ^[Yy] ]]
}

random_string() {
  openssl rand -base64 "$1" 2>/dev/null | tr -dc 'A-Za-z0-9' | head -c "$1"
}

is_vprp_dir() {
  [[ -f "$1/docker-compose.yml" && -d "$1/app" && -f "$1/Dockerfile" ]]
}

# ─── Constants ───────────────────────────────────────────────────────────────
REPO_URL="https://github.com/theblackhat55/VPRP.git"
BRANCH="main"

# ─── Start ───────────────────────────────────────────────────────────────────
banner

# ═══════════════════════════════════════════════════════════════════════════════
# Step 1: Prerequisites
# ═══════════════════════════════════════════════════════════════════════════════
step 1 "Checking prerequisites"

MISSING=()

if command -v docker &>/dev/null; then
  DOCKER_VER=$(docker --version | grep -oP '\d+\.\d+\.\d+' | head -1)
  success "Docker $DOCKER_VER"
else
  MISSING+=("docker")
  fail "Docker not found — install: https://docs.docker.com/get-docker/"
fi

COMPOSE_CMD=""
if docker compose version &>/dev/null 2>&1; then
  COMPOSE_VER=$(docker compose version --short 2>/dev/null || echo "v2+")
  COMPOSE_CMD="docker compose"
  success "Docker Compose $COMPOSE_VER (plugin)"
elif command -v docker-compose &>/dev/null; then
  COMPOSE_VER=$(docker-compose --version | grep -oP '\d+\.\d+\.\d+' | head -1)
  COMPOSE_CMD="docker-compose"
  success "Docker Compose $COMPOSE_VER (standalone)"
else
  MISSING+=("docker-compose")
  fail "Docker Compose not found"
fi

if command -v git &>/dev/null; then
  GIT_VER=$(git --version | grep -oP '\d+\.\d+\.\d+')
  success "Git $GIT_VER"
else
  MISSING+=("git")
  fail "Git not found"
fi

if command -v openssl &>/dev/null; then
  success "openssl available"
else
  MISSING+=("openssl")
  fail "openssl not found"
fi

if [[ ${#MISSING[@]} -gt 0 ]]; then
  fail "Missing: ${MISSING[*]}. Install them and re-run."
  exit 1
fi

if ! docker info &>/dev/null 2>&1; then
  fail "Docker daemon not running. Start: sudo systemctl start docker"
  exit 1
fi
success "Docker daemon running"

AVAIL_MB=$(df -m . | awk 'NR==2{print $4}')
if [[ "$AVAIL_MB" -lt 2048 ]]; then
  warn "Low disk: ${AVAIL_MB}MB (recommend 2GB+)"
else
  success "Disk space: ${AVAIL_MB}MB available"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# Step 2: Detect reverse proxy (Caddy vs Nginx)
# ═══════════════════════════════════════════════════════════════════════════════
step 2 "Detecting reverse proxy"

USE_CADDY=false
USE_NGINX=true
CADDY_CONTAINER=""
CADDY_NETWORK=""
CADDY_CADDYFILE_PATH=""

# Look for a running Caddy container
CADDY_CONTAINER=$(docker ps --filter "ancestor=caddy" --filter "status=running" --format "{{.Names}}" 2>/dev/null | head -1)
if [[ -z "$CADDY_CONTAINER" ]]; then
  # Also check by container name
  for name in caddy caddy-server caddy-proxy; do
    if docker ps --filter "name=${name}" --filter "status=running" --format "{{.Names}}" 2>/dev/null | grep -q .; then
      CADDY_CONTAINER="$name"
      break
    fi
  done
fi

if [[ -n "$CADDY_CONTAINER" ]]; then
  success "Caddy detected: container '${CADDY_CONTAINER}'"

  # Get Caddy's network
  CADDY_NETWORK=$(docker inspect "$CADDY_CONTAINER" --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>/dev/null | awk '{print $1}')
  success "Caddy network: ${CADDY_NETWORK}"

  # Find Caddyfile mount path on host
  CADDY_CADDYFILE_PATH=$(docker inspect "$CADDY_CONTAINER" --format '{{range .Mounts}}{{if eq .Destination "/etc/caddy/Caddyfile"}}{{.Source}}{{end}}{{end}}' 2>/dev/null)
  if [[ -z "$CADDY_CADDYFILE_PATH" ]]; then
    # Try alternate mount point
    CADDY_CADDYFILE_PATH=$(docker inspect "$CADDY_CONTAINER" --format '{{range .Mounts}}{{if eq .Destination "/etc/caddy"}}{{.Source}}{{end}}{{end}}' 2>/dev/null)
    if [[ -n "$CADDY_CADDYFILE_PATH" ]]; then
      CADDY_CADDYFILE_PATH="${CADDY_CADDYFILE_PATH}/Caddyfile"
    fi
  fi

  if [[ -n "$CADDY_CADDYFILE_PATH" && -f "$CADDY_CADDYFILE_PATH" ]]; then
    success "Caddyfile found: ${CADDY_CADDYFILE_PATH}"
  else
    # Caddyfile might be baked into image, we'll inject via docker exec
    CADDY_CADDYFILE_PATH=""
    info "Caddyfile not mounted — will configure via docker exec"
  fi

  echo ""
  info "Caddy is running and can serve as VPRP's reverse proxy."
  info "This means: automatic HTTPS, no self-signed cert warnings, no nginx needed."
  echo ""
  if ask_yn "Use Caddy as reverse proxy instead of nginx?" "y"; then
    USE_CADDY=true
    USE_NGINX=false
    success "Using Caddy as reverse proxy"
  else
    USE_CADDY=false
    USE_NGINX=true
    info "Using built-in nginx"
  fi
else
  info "No running Caddy container found — will use built-in nginx"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# Step 3: Repository
# ═══════════════════════════════════════════════════════════════════════════════
step 3 "Repository setup"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CURRENT_DIR="$(pwd)"

if is_vprp_dir "$CURRENT_DIR"; then
  INSTALL_DIR="$CURRENT_DIR"
  info "Already inside VPRP project: $INSTALL_DIR"
  if ask_yn "Pull latest changes?" "y"; then
    git pull origin "$BRANCH" 2>/dev/null || warn "git pull failed — using local copy"
  fi

elif is_vprp_dir "$SCRIPT_DIR"; then
  INSTALL_DIR="$SCRIPT_DIR"
  info "Deploy script is inside VPRP: $INSTALL_DIR"
  cd "$INSTALL_DIR"
  if ask_yn "Pull latest changes?" "y"; then
    git pull origin "$BRANCH" 2>/dev/null || warn "git pull failed — using local copy"
  fi

elif [[ -d "$CURRENT_DIR/VPRP" ]] && is_vprp_dir "$CURRENT_DIR/VPRP"; then
  INSTALL_DIR="$CURRENT_DIR/VPRP"
  info "Existing clone found: $INSTALL_DIR"
  cd "$INSTALL_DIR"
  if ask_yn "Pull latest changes?" "y"; then
    git pull origin "$BRANCH" 2>/dev/null || warn "git pull failed — using local copy"
  fi

else
  # Fresh clone — clone into current dir if it's named VPRP, otherwise into ./VPRP
  DIRNAME=$(basename "$CURRENT_DIR")
  if [[ "$DIRNAME" == "VPRP" ]]; then
    # We're in an empty VPRP dir — clone here
    INSTALL_DIR="$CURRENT_DIR"
    info "Cloning into current directory: $INSTALL_DIR"
    git clone -b "$BRANCH" "$REPO_URL" /tmp/vprp-clone-$$
    shopt -s dotglob
    mv /tmp/vprp-clone-$$/* "$INSTALL_DIR"/ 2>/dev/null || true
    shopt -u dotglob
    rm -rf /tmp/vprp-clone-$$
  else
    INSTALL_DIR="$CURRENT_DIR/VPRP"
    info "Cloning repository..."
    git clone -b "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
  fi
  cd "$INSTALL_DIR"
fi

cd "$INSTALL_DIR"
COMMIT_SHORT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
success "Working directory: $(pwd)"
success "Git commit: $COMMIT_SHORT"

# ═══════════════════════════════════════════════════════════════════════════════
# Step 4: Environment Configuration
# ═══════════════════════════════════════════════════════════════════════════════
step 4 "Environment configuration"

OVERWRITE_ENV=true
if [[ -f ".env" ]]; then
  warn "Existing .env file found"
  if ask_yn "Reconfigure? (No = keep existing)" "n"; then
    OVERWRITE_ENV=true
    cp .env ".env.backup.$(date +%Y%m%d_%H%M%S)"
    info "Backup saved"
  else
    OVERWRITE_ENV=false
    success "Keeping existing .env"
  fi
fi

if [[ "$OVERWRITE_ENV" == "true" ]]; then

  # ── Application ──────────────────────────────────────────────
  echo ""
  echo -e "  ${BOLD}Application Settings${NC}"
  echo -e "  ─────────────────────────────────────"
  ask APP_NAME     "Application display name"                    "VPRP"
  ask APP_ICON     "Application icon (emoji)"                    "🛡️"
  ask APP_ENV      "Environment (production/staging/development)" "production"
  APP_PORT="8501"

  # ── Database ─────────────────────────────────────────────────
  echo ""
  echo -e "  ${BOLD}Database (PostgreSQL)${NC}"
  echo -e "  ─────────────────────────────────────"
  ask POSTGRES_USER     "Database username"   "vprp"
  ask_secret POSTGRES_PASSWORD "Database password" "$(random_string 20)"
  ask POSTGRES_DB       "Database name"       "vprp_db"
  POSTGRES_HOST="vprp-postgres"
  POSTGRES_PORT="5432"
  DATABASE_URL="postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DB}"
  success "Database URL configured"

  # ── Security ─────────────────────────────────────────────────
  echo ""
  echo -e "  ${BOLD}Security${NC}"
  echo -e "  ─────────────────────────────────────"
  ask_secret SECRET_KEY    "Session secret key" "$(random_string 32)"
  ask SESSION_EXPIRY       "Session expiry (hours)" "8"

  # ── Admin ────────────────────────────────────────────────────
  echo ""
  echo -e "  ${BOLD}Initial Admin Account${NC}"
  echo -e "  ─────────────────────────────────────"
  ask ADMIN_USERNAME       "Admin username"   "admin"
  ask_secret ADMIN_PASSWORD "Admin password"  "$(random_string 16)"
  ask ADMIN_EMAIL          "Admin email (optional)" ""

  # ── Server / TLS ─────────────────────────────────────────────
  echo ""
  echo -e "  ${BOLD}Server Settings${NC}"
  echo -e "  ─────────────────────────────────────"
  DEFAULT_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
  DEFAULT_IP="${DEFAULT_IP:-localhost}"
  ask SERVER_DOMAIN "Server domain or IP" "$DEFAULT_IP"

  if [[ "$USE_CADDY" == "true" ]]; then
    info "Caddy handles TLS automatically — no certificate setup needed"
    TLS_OPTION="caddy"
    PROXY_MODE="caddy"

    ask VPRP_PORT "Port for VPRP web interface" "9443"
  else
    echo ""
    echo -e "    ${CYAN}1)${NC} Self-signed certificate (auto-generated)"
    echo -e "    ${CYAN}2)${NC} Let's Encrypt (requires public domain)"
    echo -e "    ${CYAN}3)${NC} Custom certificate (bring your own)"
    echo -e "    ${CYAN}4)${NC} None / HTTP only"
    read -rp "$(echo -e "  ${CYAN}?${NC} TLS option [1]: ")" TLS_OPTION
    TLS_OPTION="${TLS_OPTION:-1}"
    PROXY_MODE="nginx"

    # Port selection for nginx
    HTTP_PORT="80"
    HTTPS_PORT="443"
    for port in 80 443; do
      if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
        warn "Port $port is in use"
        if [[ "$port" == "80" ]]; then
          ask HTTP_PORT "HTTP port (80 taken)" "8080"
        else
          ask HTTPS_PORT "HTTPS port (443 taken)" "9443"
        fi
      fi
    done
    VPRP_PORT="${HTTPS_PORT}"
  fi

  # ── Notifications ────────────────────────────────────────────
  echo ""
  echo -e "  ${BOLD}Email Notifications (optional)${NC}"
  echo -e "  ─────────────────────────────────────"
  SMTP_ENABLED="false"
  SMTP_HOST=""; SMTP_PORT="587"; SMTP_USER=""; SMTP_PASSWORD=""; SMTP_FROM=""; SMTP_TLS="true"

  if ask_yn "Enable email notifications?" "n"; then
    SMTP_ENABLED="true"
    ask SMTP_HOST         "SMTP host"            "smtp.gmail.com"
    ask SMTP_PORT         "SMTP port"            "587"
    ask SMTP_USER         "SMTP username"        ""
    ask_secret SMTP_PASSWORD "SMTP password"     ""
    ask SMTP_FROM         "From email"           "${SMTP_USER}"
    ask SMTP_TLS          "Use TLS? (true/false)" "true"
  fi

  # ── Backups ──────────────────────────────────────────────────
  echo ""
  echo -e "  ${BOLD}Backup Settings${NC}"
  echo -e "  ─────────────────────────────────────"
  ask BACKUP_ENABLED      "Enable automatic backups? (true/false)" "true"
  ask BACKUP_RETENTION    "Retention (days)"       "30"
  ask BACKUP_DIR          "Backup directory"       "./backups"

  # ── Advanced ─────────────────────────────────────────────────
  echo ""
  echo -e "  ${BOLD}Advanced${NC}"
  echo -e "  ─────────────────────────────────────"
  ask MAX_UPLOAD_SIZE     "Max upload size (MB)"   "200"
  ask LOG_LEVEL           "Log level (DEBUG/INFO/WARNING/ERROR)" "INFO"

  # ── Write .env ───────────────────────────────────────────────
  echo ""
  info "Writing .env file..."

  cat > .env <<ENVFILE
# ═══════════════════════════════════════════════════════════════════════
# VPRP – Environment Configuration
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ") by deploy.sh v1.2
# ═══════════════════════════════════════════════════════════════════════

# ── Application ───────────────────────────────────────────────────────
APP_NAME=${APP_NAME}
APP_ICON=${APP_ICON}
APP_ENV=${APP_ENV}
APP_PORT=${APP_PORT}
LOG_LEVEL=${LOG_LEVEL}

# ── Database ──────────────────────────────────────────────────────────
POSTGRES_USER=${POSTGRES_USER}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
POSTGRES_DB=${POSTGRES_DB}
POSTGRES_HOST=${POSTGRES_HOST}
POSTGRES_PORT=${POSTGRES_PORT}
DATABASE_URL=${DATABASE_URL}

# ── Security ──────────────────────────────────────────────────────────
SECRET_KEY=${SECRET_KEY}
SESSION_EXPIRY_HOURS=${SESSION_EXPIRY}

# ── Admin ─────────────────────────────────────────────────────────────
ADMIN_USERNAME=${ADMIN_USERNAME}
ADMIN_PASSWORD=${ADMIN_PASSWORD}
ADMIN_EMAIL=${ADMIN_EMAIL}

# ── Server / Proxy ────────────────────────────────────────────────────
SERVER_DOMAIN=${SERVER_DOMAIN}
PROXY_MODE=${PROXY_MODE}
TLS_OPTION=${TLS_OPTION}
VPRP_PORT=${VPRP_PORT:-443}
HTTP_PORT=${HTTP_PORT:-80}
HTTPS_PORT=${HTTPS_PORT:-443}
MAX_UPLOAD_SIZE=${MAX_UPLOAD_SIZE}

# ── Caddy (if applicable) ────────────────────────────────────────────
CADDY_CONTAINER=${CADDY_CONTAINER}
CADDY_NETWORK=${CADDY_NETWORK}

# ── Email ─────────────────────────────────────────────────────────────
SMTP_ENABLED=${SMTP_ENABLED}
SMTP_HOST=${SMTP_HOST}
SMTP_PORT=${SMTP_PORT}
SMTP_USER=${SMTP_USER}
SMTP_PASSWORD=${SMTP_PASSWORD}
SMTP_FROM=${SMTP_FROM}
SMTP_TLS=${SMTP_TLS}

# ── Backups ───────────────────────────────────────────────────────────
BACKUP_ENABLED=${BACKUP_ENABLED}
BACKUP_RETENTION_DAYS=${BACKUP_RETENTION}
BACKUP_DIR=${BACKUP_DIR}
ENVFILE

  chmod 600 .env
  success ".env written (mode 600)"

fi  # end OVERWRITE_ENV

# Source .env
set -a
source .env
set +a

# ═══════════════════════════════════════════════════════════════════════════════
# Step 5: TLS / Proxy Setup
# ═══════════════════════════════════════════════════════════════════════════════
step 5 "Reverse proxy & TLS setup"

PROXY_MODE="${PROXY_MODE:-nginx}"

if [[ "$PROXY_MODE" == "caddy" ]]; then
  # ── Caddy setup ────────────────────────────────────────────
  info "Configuring Caddy as reverse proxy for VPRP..."

  CADDY_CONTAINER="${CADDY_CONTAINER:-caddy}"
  CADDY_NETWORK="${CADDY_NETWORK:-}"
  VPRP_PORT="${VPRP_PORT:-9443}"
  VPRP_DOCKER_NETWORK=$(grep -A 5 "networks:" docker-compose.yml | grep -oP '\w+-net' | head -1 || echo "vprp_vprp-net")

  # Build the Caddy snippet for VPRP
  CADDY_VPRP_BLOCK=":${VPRP_PORT} {
    reverse_proxy vprp-app:8501
    encode gzip
    header {
        X-Content-Type-Options nosniff
        X-Frame-Options SAMEORIGIN
        Referrer-Policy strict-origin-when-cross-origin
    }
}"

  # Check if VPRP block already exists in Caddyfile
  ALREADY_CONFIGURED=false
  if [[ -n "$CADDY_CADDYFILE_PATH" && -f "$CADDY_CADDYFILE_PATH" ]]; then
    if grep -q "vprp-app:8501" "$CADDY_CADDYFILE_PATH" 2>/dev/null; then
      ALREADY_CONFIGURED=true
      info "VPRP already configured in Caddyfile"
      if ask_yn "Update Caddy config?" "n"; then
        ALREADY_CONFIGURED=false
        # Remove old VPRP block
        sed -i '/# VPRP-START/,/# VPRP-END/d' "$CADDY_CADDYFILE_PATH"
      fi
    fi

    if [[ "$ALREADY_CONFIGURED" == "false" ]]; then
      info "Adding VPRP block to ${CADDY_CADDYFILE_PATH}"
      cat >> "$CADDY_CADDYFILE_PATH" <<CADDYBLOCK

# VPRP-START — managed by VPRP deploy.sh
:${VPRP_PORT} {
    reverse_proxy vprp-app:8501
    encode gzip
    header {
        X-Content-Type-Options nosniff
        X-Frame-Options SAMEORIGIN
        Referrer-Policy strict-origin-when-cross-origin
    }
}
# VPRP-END
CADDYBLOCK
      success "Caddyfile updated"
    fi
  else
    # No host-mounted Caddyfile — inject via docker exec
    info "Injecting VPRP config into Caddy container..."
    EXISTING_CONFIG=$(docker exec "$CADDY_CONTAINER" cat /etc/caddy/Caddyfile 2>/dev/null)

    if echo "$EXISTING_CONFIG" | grep -q "vprp-app:8501"; then
      info "VPRP already configured in Caddy"
    else
      # Append VPRP block
      NEW_CONFIG="${EXISTING_CONFIG}

# VPRP-START — managed by VPRP deploy.sh
:${VPRP_PORT} {
    reverse_proxy vprp-app:8501
    encode gzip
    header {
        X-Content-Type-Options nosniff
        X-Frame-Options SAMEORIGIN
        Referrer-Policy strict-origin-when-cross-origin
    }
}
# VPRP-END"

      echo "$NEW_CONFIG" | docker exec -i "$CADDY_CONTAINER" tee /etc/caddy/Caddyfile > /dev/null
      success "Caddy config injected"
    fi
  fi

  # We don't need nginx — remove it from compose if present
  info "Nginx will be skipped (Caddy handles reverse proxy)"

else
  # ── Nginx TLS setup ────────────────────────────────────────
  mkdir -p nginx/certs

  case "${TLS_OPTION:-1}" in
    1)
      REGEN=true
      if [[ -f "nginx/certs/selfsigned.crt" ]]; then
        CERT_EXP=$(openssl x509 -enddate -noout -in nginx/certs/selfsigned.crt 2>/dev/null | cut -d= -f2)
        info "Existing cert (expires: ${CERT_EXP:-unknown})"
        if ! ask_yn "Regenerate?" "n"; then
          REGEN=false
        fi
      fi
      if [[ "$REGEN" == "true" ]]; then
        SAN="DNS:${SERVER_DOMAIN}"
        [[ "${SERVER_DOMAIN}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && SAN="IP:${SERVER_DOMAIN}"
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
          -keyout nginx/certs/selfsigned.key \
          -out nginx/certs/selfsigned.crt \
          -subj "/C=US/ST=Local/L=Local/O=VPRP/CN=${SERVER_DOMAIN}" \
          -addext "subjectAltName=${SAN}" 2>/dev/null
        chmod 600 nginx/certs/selfsigned.key
        success "Self-signed cert generated"
      fi
      ;;
    2)
      info "Let's Encrypt — temporary cert for startup"
      if [[ ! -f "nginx/certs/selfsigned.crt" ]]; then
        openssl req -x509 -nodes -days 30 -newkey rsa:2048 \
          -keyout nginx/certs/selfsigned.key \
          -out nginx/certs/selfsigned.crt \
          -subj "/CN=${SERVER_DOMAIN}" 2>/dev/null
      fi
      ;;
    3)
      ask CERT_PATH "Certificate path (.crt/.pem)" ""
      ask KEY_PATH  "Private key path (.key)"       ""
      if [[ -f "$CERT_PATH" && -f "$KEY_PATH" ]]; then
        cp "$CERT_PATH" nginx/certs/selfsigned.crt
        cp "$KEY_PATH"  nginx/certs/selfsigned.key
        chmod 600 nginx/certs/selfsigned.key
        success "Custom cert installed"
      else
        fail "Files not found — generating self-signed"
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
          -keyout nginx/certs/selfsigned.key \
          -out nginx/certs/selfsigned.crt \
          -subj "/CN=${SERVER_DOMAIN}" 2>/dev/null
      fi
      ;;
    4)
      warn "No TLS — not recommended"
      if [[ ! -f "nginx/certs/selfsigned.crt" ]]; then
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
          -keyout nginx/certs/selfsigned.key \
          -out nginx/certs/selfsigned.crt \
          -subj "/CN=localhost" 2>/dev/null
      fi
      ;;
  esac
fi

# ═══════════════════════════════════════════════════════════════════════════════
# Step 6: Pre-flight
# ═══════════════════════════════════════════════════════════════════════════════
step 6 "Pre-flight checks"

mkdir -p "${BACKUP_DIR:-./backups}" data logs
success "Directories created"

if [[ ! -f "docker-compose.yml" ]]; then
  fail "docker-compose.yml not found"
  exit 1
fi
success "docker-compose.yml found"

COMPOSE_FILES="-f docker-compose.yml"
if [[ -f "docker-compose.prod.yml" ]]; then
  COMPOSE_FILES="$COMPOSE_FILES -f docker-compose.prod.yml"
  success "docker-compose.prod.yml found"
fi

# Validate .env
PREFLIGHT_PASS=true
for var in POSTGRES_USER POSTGRES_PASSWORD POSTGRES_DB DATABASE_URL SECRET_KEY; do
  if [[ -z "${!var:-}" ]]; then
    fail "Missing: $var"
    PREFLIGHT_PASS=false
  fi
done
[[ "$PREFLIGHT_PASS" == "true" ]] && success "Environment variables OK" || { fail "Fix .env"; exit 1; }

# Update nginx ports in compose if needed (nginx mode only)
if [[ "$PROXY_MODE" != "caddy" ]]; then
  HTTP_PORT="${HTTP_PORT:-80}"
  HTTPS_PORT="${HTTPS_PORT:-443}"
  if [[ "$HTTP_PORT" != "80" || "$HTTPS_PORT" != "443" ]]; then
    if [[ -f "docker-compose.prod.yml" ]]; then
      sed -i "s|\"80:80\"|\"${HTTP_PORT}:80\"|g"     docker-compose.prod.yml
      sed -i "s|\"443:443\"|\"${HTTPS_PORT}:443\"|g"  docker-compose.prod.yml
      success "Nginx ports updated: ${HTTP_PORT}:80, ${HTTPS_PORT}:443"
    fi
  fi
fi

# Stop existing VPRP containers
RUNNING=$(docker ps -q --filter "name=vprp-" 2>/dev/null | wc -l)
if [[ "$RUNNING" -gt 0 ]]; then
  info "Stopping existing VPRP containers..."
  $COMPOSE_CMD $COMPOSE_FILES down 2>/dev/null || true
  success "Previous containers stopped"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# Step 7: Build & Start
# ═══════════════════════════════════════════════════════════════════════════════
step 7 "Building and starting containers"

info "Pulling base images..."
$COMPOSE_CMD $COMPOSE_FILES pull --ignore-buildable 2>/dev/null || true

info "Building application image..."
if ! $COMPOSE_CMD $COMPOSE_FILES build app; then
  fail "Build failed"
  exit 1
fi

if [[ "$PROXY_MODE" == "caddy" ]]; then
  # Start only app + postgres, skip nginx
  info "Starting app and database (Caddy handles proxy)..."
  $COMPOSE_CMD $COMPOSE_FILES up -d app postgres 2>/dev/null \
    || $COMPOSE_CMD $COMPOSE_FILES up -d 2>/dev/null

  # Stop nginx if it started
  docker stop vprp-nginx 2>/dev/null || true
  docker rm vprp-nginx 2>/dev/null || true
else
  info "Starting all services..."
  if ! $COMPOSE_CMD $COMPOSE_FILES up -d; then
    fail "Failed to start"
    exit 1
  fi
fi
echo ""

# ── Health check loop ────────────────────────────────────────
info "Waiting for services..."
MAX_WAIT=120
ELAPSED=0
HEALTHY=false

while [[ $ELAPSED -lt $MAX_WAIT ]]; do
  PG_STATUS=$(docker inspect --format='{{.State.Health.Status}}' vprp-postgres 2>/dev/null || echo "waiting")
  APP_STATE=$(docker inspect --format='{{.State.Status}}' vprp-app 2>/dev/null || echo "waiting")
  APP_RESTART=$(docker inspect --format='{{.RestartCount}}' vprp-app 2>/dev/null || echo "0")

  if [[ "$APP_RESTART" -gt 3 ]]; then
    echo ""
    fail "App crash-looping (${APP_RESTART} restarts)"
    $COMPOSE_CMD $COMPOSE_FILES logs --tail 30 app 2>/dev/null || true
    exit 1
  fi

  if [[ "$PG_STATUS" == "healthy" && "$APP_STATE" == "running" ]]; then
    HTTP_CODE=$(docker exec vprp-app curl -s -o /dev/null -w "%{http_code}" http://localhost:8501/_stcore/health 2>/dev/null || echo "000")
    if [[ "$HTTP_CODE" == "200" ]]; then
      HEALTHY=true
      break
    fi
  fi

  printf "\r  ⏳ %ds / %ds  [postgres: %-8s  app: %-10s]" "$ELAPSED" "$MAX_WAIT" "$PG_STATUS" "$APP_STATE"
  sleep 5
  ELAPSED=$((ELAPSED + 5))
done
echo ""

if [[ "$HEALTHY" != "true" ]]; then
  fail "Not healthy after ${MAX_WAIT}s"
  echo "  $COMPOSE_CMD $COMPOSE_FILES logs --tail 50 app"
  exit 1
fi

success "PostgreSQL: healthy"
success "Application: running (HTTP 200)"

# ═══════════════════════════════════════════════════════════════════════════════
# Step 8: Connect Caddy to VPRP network (if Caddy mode)
# ═══════════════════════════════════════════════════════════════════════════════
if [[ "$PROXY_MODE" == "caddy" ]]; then
  step 8 "Connecting Caddy to VPRP"

  # Find the VPRP network name
  VPRP_NETWORK=$(docker inspect vprp-app --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>/dev/null | awk '{print $1}')

  if [[ -n "$VPRP_NETWORK" ]]; then
    info "VPRP network: ${VPRP_NETWORK}"

    # Connect Caddy to VPRP network
    if docker network connect "$VPRP_NETWORK" "$CADDY_CONTAINER" 2>/dev/null; then
      success "Caddy connected to ${VPRP_NETWORK}"
    else
      info "Caddy already on ${VPRP_NETWORK} (or connection exists)"
    fi

    # Verify connectivity
    if docker exec "$CADDY_CONTAINER" wget -q -O /dev/null --timeout=5 http://vprp-app:8501/_stcore/health 2>/dev/null; then
      success "Caddy → vprp-app connectivity verified"
    else
      warn "Connectivity check failed — trying with IP fallback"
      VPRP_IP=$(docker inspect vprp-app --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null)
      if docker exec "$CADDY_CONTAINER" wget -q -O /dev/null --timeout=5 "http://${VPRP_IP}:8501/_stcore/health" 2>/dev/null; then
        success "Caddy → vprp-app OK via IP (${VPRP_IP})"
        warn "Using IP in Caddy config instead of hostname"
        # Update Caddy config to use IP
        if [[ -n "$CADDY_CADDYFILE_PATH" && -f "$CADDY_CADDYFILE_PATH" ]]; then
          sed -i "s|vprp-app:8501|${VPRP_IP}:8501|g" "$CADDY_CADDYFILE_PATH"
        else
          docker exec "$CADDY_CONTAINER" sed -i "s|vprp-app:8501|${VPRP_IP}:8501|g" /etc/caddy/Caddyfile 2>/dev/null || true
        fi
      else
        fail "Cannot reach vprp-app from Caddy"
        warn "You may need to manually configure networking"
      fi
    fi

    # Reload Caddy
    info "Reloading Caddy configuration..."
    docker exec "$CADDY_CONTAINER" caddy reload --config /etc/caddy/Caddyfile 2>/dev/null \
      && success "Caddy reloaded" \
      || warn "Caddy reload failed — try: docker restart $CADDY_CONTAINER"

    # Verify VPRP is accessible through Caddy
    sleep 2
    VPRP_PORT="${VPRP_PORT:-9443}"
    CADDY_CHECK=$(docker exec "$CADDY_CONTAINER" wget -q -O /dev/null --timeout=5 "http://localhost:${VPRP_PORT}" 2>/dev/null && echo "OK" || echo "FAIL")
    if [[ "$CADDY_CHECK" == "OK" ]]; then
      success "VPRP accessible via Caddy on port ${VPRP_PORT}"
    else
      info "Direct check inconclusive — try browser access"
    fi
  else
    warn "Could not determine VPRP network"
  fi

  NEXT_STEP=9
else
  NEXT_STEP=9
fi

# ═══════════════════════════════════════════════════════════════════════════════
# Step 9: Database Migrations
# ═══════════════════════════════════════════════════════════════════════════════
step "$NEXT_STEP" "Running database migrations"

MIGRATION_OUTPUT=$(docker exec vprp-app alembic -c /app/alembic.ini upgrade head 2>&1) || true

if echo "$MIGRATION_OUTPUT" | grep -qiE "error|traceback"; then
  warn "Migration warnings:"
  echo "$MIGRATION_OUTPUT" | tail -5
else
  success "Migrations applied"
fi

ALEMBIC_REV=$(docker exec vprp-app alembic -c /app/alembic.ini current 2>&1 | grep -oP '[a-f0-9]{12}' | head -1 || echo "unknown")
success "Alembic: ${ALEMBIC_REV}"

# Table check
TABLE_CHECK=$(docker exec vprp-app python -c "
from app.models.database import engine
from sqlalchemy import inspect
tables = inspect(engine).get_table_names()
required = ['findings', 'assets', 'asset_groups', 'users', 'scan_uploads']
missing = [t for t in required if t not in tables]
print(f'MISSING:{chr(44).join(missing)}' if missing else f'OK:{len(tables)}')
" 2>&1) || true

if [[ "$TABLE_CHECK" == OK* ]]; then
  success "Schema verified (${TABLE_CHECK#OK:} tables)"
else
  warn "Schema: $TABLE_CHECK"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# Step 10: Create Admin User
# ═══════════════════════════════════════════════════════════════════════════════
step "$((NEXT_STEP + 1))" "Creating admin user"

ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-}"

if [[ -z "$ADMIN_PASSWORD" ]]; then
  warn "No ADMIN_PASSWORD — skipping"
else
  ESCAPED_PW=$(echo "$ADMIN_PASSWORD" | sed "s/'/\\\\'/g")
  ADMIN_RESULT=$(docker exec vprp-app python -c "
try:
    from app.models.auth_service import create_user, list_users
    users = list_users()
    existing = [u for u in users if u.get('username') == '${ADMIN_USERNAME}']
    if existing:
        print('EXISTS')
    else:
        result = create_user('${ADMIN_USERNAME}', '${ESCAPED_PW}', 'admin')
        print('CREATED' if result else 'FAILED')
except Exception as e:
    print(f'ERROR:{e}')
" 2>&1) || true

  case "$ADMIN_RESULT" in
    *EXISTS*)  info "Admin '${ADMIN_USERNAME}' already exists" ;;
    *CREATED*) success "Admin '${ADMIN_USERNAME}' created" ;;
    *ERROR*)   warn "Admin creation: ${ADMIN_RESULT#*ERROR:}" ;;
    *)         warn "Result: $ADMIN_RESULT" ;;
  esac
fi

# ═══════════════════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════════════════
echo ""
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║                                                                  ║${NC}"
echo -e "${GREEN}${BOLD}║            🛡️  VPRP Deployed Successfully!                        ║${NC}"
echo -e "${GREEN}${BOLD}║                                                                  ║${NC}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════════════╝${NC}"

echo ""
echo -e "  ${BOLD}Access URL${NC}"
echo -e "  ─────────────────────────────────────────────────"
if [[ "$PROXY_MODE" == "caddy" ]]; then
  VPRP_PORT="${VPRP_PORT:-9443}"
  echo -e "    ${CYAN}https://${SERVER_DOMAIN}:${VPRP_PORT}/${NC}"
  echo ""
  echo -e "  ${BOLD}Proxy${NC}: Caddy (container: ${CADDY_CONTAINER})"
else
  HTTP_PORT="${HTTP_PORT:-80}"
  HTTPS_PORT="${HTTPS_PORT:-443}"
  if [[ "$HTTPS_PORT" == "443" ]]; then
    echo -e "    HTTPS:  ${CYAN}https://${SERVER_DOMAIN}/${NC}"
  else
    echo -e "    HTTPS:  ${CYAN}https://${SERVER_DOMAIN}:${HTTPS_PORT}/${NC}"
  fi
  echo ""
  echo -e "  ${BOLD}Proxy${NC}: nginx (built-in)"
fi

echo ""
echo -e "  ${BOLD}Admin Login${NC}"
echo -e "  ─────────────────────────────────────────────────"
echo -e "    Username:  ${CYAN}${ADMIN_USERNAME}${NC}"
if [[ -n "${ADMIN_PASSWORD:-}" ]]; then
  PW_LEN=${#ADMIN_PASSWORD}
  if [[ $PW_LEN -gt 3 ]]; then
    MASKED="${ADMIN_PASSWORD:0:3}$(printf '*%.0s' $(seq 1 $((PW_LEN - 3))))"
  else
    MASKED="***"
  fi
  echo -e "    Password:  ${CYAN}${MASKED}${NC}  (see .env)"
fi

echo ""
echo -e "  ${BOLD}Containers${NC}"
echo -e "  ─────────────────────────────────────────────────"
docker ps --filter "name=vprp-" --format "    {{.Names}}  {{.Status}}" 2>/dev/null

echo ""
echo -e "  ${BOLD}Commands${NC}"
echo -e "  ─────────────────────────────────────────────────"
echo -e "    View logs:      ${CYAN}cd $(pwd) && $COMPOSE_CMD $COMPOSE_FILES logs -f app${NC}"
echo -e "    Stop:           ${CYAN}cd $(pwd) && $COMPOSE_CMD $COMPOSE_FILES down${NC}"
echo -e "    Restart:        ${CYAN}docker restart vprp-app${NC}"
echo -e "    Rebuild:        ${CYAN}cd $(pwd) && $COMPOSE_CMD $COMPOSE_FILES up -d --build app${NC}"
echo -e "    DB backup:      ${CYAN}docker exec vprp-postgres pg_dump -U ${POSTGRES_USER} ${POSTGRES_DB} > backup.sql${NC}"
echo -e "    DB shell:       ${CYAN}docker exec -it vprp-postgres psql -U ${POSTGRES_USER} ${POSTGRES_DB}${NC}"
echo -e "    App shell:      ${CYAN}docker exec -it vprp-app /bin/bash${NC}"

echo ""
echo -e "  ${BOLD}Files${NC}"
echo -e "  ─────────────────────────────────────────────────"
echo -e "    Project:     ${CYAN}$(pwd)${NC}"
echo -e "    Config:      ${CYAN}$(pwd)/.env${NC}"
echo -e "    Backups:     ${CYAN}$(pwd)/${BACKUP_DIR:-./backups}${NC}"

if [[ "$PROXY_MODE" != "caddy" && "${TLS_OPTION:-1}" == "1" ]]; then
  echo ""
  warn "Self-signed cert — browser will show a security warning (normal)."
fi

echo ""
success "Done! $(date -u +'%Y-%m-%d %H:%M:%S UTC')"
echo ""

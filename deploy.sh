#!/usr/bin/env bash
###############################################################################
# VPRP – Vulnerability Prioritization & Remediation Platform
# Interactive Deployment Script v1.1
#
# Usage:
#   chmod +x deploy.sh && ./deploy.sh
#
# Can be run from:
#   - Inside the VPRP project directory (skips clone)
#   - Outside the VPRP directory (clones or updates)
#   - Any location — detects context automatically
###############################################################################
set -uo pipefail
# NOTE: 'set -e' intentionally omitted — we handle errors manually

# ─── Colors & helpers ────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

banner() {
  clear
  echo ""
  echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${CYAN}${BOLD}║                                                                  ║${NC}"
  echo -e "${CYAN}${BOLD}║     🛡️  VPRP – Vulnerability Prioritization & Remediation        ║${NC}"
  echo -e "${CYAN}${BOLD}║                    Deployment Script v1.1                        ║${NC}"
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

# Docker
if command -v docker &>/dev/null; then
  DOCKER_VER=$(docker --version | grep -oP '\d+\.\d+\.\d+' | head -1)
  success "Docker $DOCKER_VER"
else
  MISSING+=("docker")
  fail "Docker not found — install: https://docs.docker.com/get-docker/"
fi

# Docker Compose
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
  fail "Docker Compose not found — install: https://docs.docker.com/compose/install/"
fi

# Git
if command -v git &>/dev/null; then
  GIT_VER=$(git --version | grep -oP '\d+\.\d+\.\d+')
  success "Git $GIT_VER"
else
  MISSING+=("git")
  fail "Git not found — install: sudo apt install git"
fi

# openssl
if command -v openssl &>/dev/null; then
  success "openssl available"
else
  MISSING+=("openssl")
  fail "openssl not found — install: sudo apt install openssl"
fi

# Abort if missing
if [[ ${#MISSING[@]} -gt 0 ]]; then
  echo ""
  fail "Missing prerequisites: ${MISSING[*]}"
  echo "  Install them and re-run this script."
  exit 1
fi

# Docker daemon
if ! docker info &>/dev/null 2>&1; then
  fail "Docker daemon is not running. Start it first:"
  echo "    sudo systemctl start docker"
  exit 1
fi
success "Docker daemon is running"

# Disk space check
AVAIL_MB=$(df -m . | awk 'NR==2{print $4}')
if [[ "$AVAIL_MB" -lt 2048 ]]; then
  warn "Low disk space: ${AVAIL_MB}MB available (recommend 2GB+)"
else
  success "Disk space: ${AVAIL_MB}MB available"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# Step 2: Repository
# ═══════════════════════════════════════════════════════════════════════════════
step 2 "Repository setup"

is_vprp_dir() {
  # Returns 0 if the given directory looks like the VPRP project
  [[ -f "$1/docker-compose.yml" && -d "$1/app" && -f "$1/Dockerfile" ]]
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CURRENT_DIR="$(pwd)"

if is_vprp_dir "$CURRENT_DIR"; then
  # Running from inside the VPRP directory
  INSTALL_DIR="$CURRENT_DIR"
  info "Already inside VPRP project: $INSTALL_DIR"
  if ask_yn "Pull latest changes from remote?" "y"; then
    git pull origin "$BRANCH" 2>/dev/null || warn "git pull failed — continuing with local copy"
  fi

elif is_vprp_dir "$SCRIPT_DIR"; then
  # Script lives inside the VPRP directory, but user ran from elsewhere
  INSTALL_DIR="$SCRIPT_DIR"
  info "Deploy script is inside VPRP project: $INSTALL_DIR"
  cd "$INSTALL_DIR"
  if ask_yn "Pull latest changes from remote?" "y"; then
    git pull origin "$BRANCH" 2>/dev/null || warn "git pull failed — continuing with local copy"
  fi

elif [[ -d "$CURRENT_DIR/VPRP" ]] && is_vprp_dir "$CURRENT_DIR/VPRP"; then
  # ./VPRP subdirectory already exists
  INSTALL_DIR="$CURRENT_DIR/VPRP"
  info "Existing VPRP clone found: $INSTALL_DIR"
  cd "$INSTALL_DIR"
  if ask_yn "Pull latest changes from remote?" "y"; then
    git pull origin "$BRANCH" 2>/dev/null || warn "git pull failed — continuing with local copy"
  fi

else
  # Fresh clone needed
  INSTALL_DIR="$CURRENT_DIR/VPRP"
  info "Cloning VPRP from public repository..."
  info "Target: $INSTALL_DIR"
  git clone -b "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
  cd "$INSTALL_DIR"
fi

cd "$INSTALL_DIR"
COMMIT_SHORT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
success "Working directory: $(pwd)"
success "Git commit: $COMMIT_SHORT"

# ═══════════════════════════════════════════════════════════════════════════════
# Step 3: Environment Configuration
# ═══════════════════════════════════════════════════════════════════════════════
step 3 "Environment configuration"

OVERWRITE_ENV=true
if [[ -f ".env" ]]; then
  warn "Existing .env file found"
  if ask_yn "Reconfigure? (No = keep existing settings)" "n"; then
    OVERWRITE_ENV=true
    cp .env ".env.backup.$(date +%Y%m%d_%H%M%S)"
    info "Backup saved as .env.backup.*"
  else
    OVERWRITE_ENV=false
    success "Keeping existing .env"
  fi
fi

if [[ "$OVERWRITE_ENV" == "true" ]]; then

  # ── 3a. Application ──────────────────────────────────────────
  echo ""
  echo -e "  ${BOLD}Application Settings${NC}"
  echo -e "  ─────────────────────────────────────"
  ask APP_NAME     "Application display name"                    "VPRP"
  ask APP_ICON     "Application icon (emoji)"                    "🛡️"
  ask APP_ENV      "Environment (production/staging/development)" "production"
  ask APP_PORT     "Streamlit port (internal)"                   "8501"

  # ── 3b. Database ─────────────────────────────────────────────
  echo ""
  echo -e "  ${BOLD}Database (PostgreSQL)${NC}"
  echo -e "  ─────────────────────────────────────"
  ask POSTGRES_USER     "Database username"   "vprp"
  ask_secret POSTGRES_PASSWORD "Database password" "$(random_string 20)"
  ask POSTGRES_DB       "Database name"       "vprp_db"
  POSTGRES_HOST="vprp-postgres"
  POSTGRES_PORT="5432"
  DATABASE_URL="postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DB}"
  success "Database URL configured (internal Docker network)"

  # ── 3c. Security ─────────────────────────────────────────────
  echo ""
  echo -e "  ${BOLD}Security${NC}"
  echo -e "  ─────────────────────────────────────"
  DEFAULT_SECRET=$(random_string 32)
  ask_secret SECRET_KEY    "Session secret key" "$DEFAULT_SECRET"
  ask SESSION_EXPIRY       "Session expiry in hours" "8"

  # ── 3d. Admin Account ───────────────────────────────────────
  echo ""
  echo -e "  ${BOLD}Initial Admin Account${NC}"
  echo -e "  ─────────────────────────────────────"
  ask ADMIN_USERNAME       "Admin username"   "admin"
  ask_secret ADMIN_PASSWORD "Admin password"  "$(random_string 16)"
  ask ADMIN_EMAIL          "Admin email (optional, for notifications)" ""

  # ── 3e. TLS / HTTPS ─────────────────────────────────────────
  echo ""
  echo -e "  ${BOLD}TLS / HTTPS${NC}"
  echo -e "  ─────────────────────────────────────"
  echo -e "    ${CYAN}1)${NC} Self-signed certificate (auto-generated)"
  echo -e "    ${CYAN}2)${NC} Let's Encrypt (requires public domain)"
  echo -e "    ${CYAN}3)${NC} Custom certificate (bring your own)"
  echo -e "    ${CYAN}4)${NC} None / HTTP only"
  read -rp "$(echo -e "  ${CYAN}?${NC} TLS option [1]: ")" TLS_OPTION
  TLS_OPTION="${TLS_OPTION:-1}"

  DEFAULT_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
  DEFAULT_IP="${DEFAULT_IP:-localhost}"
  ask SERVER_DOMAIN "Server domain or IP address" "$DEFAULT_IP"

  # ── 3f. HTTP/HTTPS Ports ─────────────────────────────────────
  echo ""
  echo -e "  ${BOLD}Web Server Ports${NC}"
  echo -e "  ─────────────────────────────────────"

  # Check if 80/443 are in use
  PORT_80_FREE=true
  PORT_443_FREE=true
  if ss -tlnp 2>/dev/null | grep -q ":80 " || netstat -tlnp 2>/dev/null | grep -q ":80 "; then
    PORT_80_FREE=false
    warn "Port 80 is already in use on this machine"
  fi
  if ss -tlnp 2>/dev/null | grep -q ":443 " || netstat -tlnp 2>/dev/null | grep -q ":443 "; then
    PORT_443_FREE=false
    warn "Port 443 is already in use on this machine"
  fi

  if [[ "$PORT_80_FREE" == "true" ]]; then
    ask HTTP_PORT  "HTTP port"  "80"
  else
    ask HTTP_PORT  "HTTP port (80 is taken)"  "8080"
  fi
  if [[ "$PORT_443_FREE" == "true" ]]; then
    ask HTTPS_PORT "HTTPS port" "443"
  else
    ask HTTPS_PORT "HTTPS port (443 is taken)" "8443"
  fi

  # ── 3g. Notifications ───────────────────────────────────────
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
    ask SMTP_FROM         "From email address"   "${SMTP_USER}"
    ask SMTP_TLS          "Use TLS? (true/false)" "true"
  fi

  # ── 3h. Backups ─────────────────────────────────────────────
  echo ""
  echo -e "  ${BOLD}Backup Settings${NC}"
  echo -e "  ─────────────────────────────────────"
  ask BACKUP_ENABLED      "Enable automatic backups? (true/false)" "true"
  ask BACKUP_RETENTION    "Backup retention in days"               "30"
  ask BACKUP_DIR          "Backup directory"                       "./backups"

  # ── 3i. Advanced ────────────────────────────────────────────
  echo ""
  echo -e "  ${BOLD}Advanced Settings${NC}"
  echo -e "  ─────────────────────────────────────"
  ask MAX_UPLOAD_SIZE     "Max file upload size in MB"             "200"
  ask LOG_LEVEL           "Log level (DEBUG/INFO/WARNING/ERROR)"   "INFO"

  # ── Write .env ──────────────────────────────────────────────
  echo ""
  info "Writing .env file..."

  cat > .env <<ENVFILE
# ═══════════════════════════════════════════════════════════════════════
# VPRP – Environment Configuration
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ") by deploy.sh
# ═══════════════════════════════════════════════════════════════════════

# ── Application ───────────────────────────────────────────────────────
APP_NAME=${APP_NAME}
APP_ICON=${APP_ICON}
APP_ENV=${APP_ENV}
APP_PORT=${APP_PORT}
LOG_LEVEL=${LOG_LEVEL}

# ── Database (PostgreSQL) ─────────────────────────────────────────────
POSTGRES_USER=${POSTGRES_USER}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
POSTGRES_DB=${POSTGRES_DB}
POSTGRES_HOST=${POSTGRES_HOST}
POSTGRES_PORT=${POSTGRES_PORT}
DATABASE_URL=${DATABASE_URL}

# ── Security ──────────────────────────────────────────────────────────
SECRET_KEY=${SECRET_KEY}
SESSION_EXPIRY_HOURS=${SESSION_EXPIRY}

# ── Admin Account ─────────────────────────────────────────────────────
ADMIN_USERNAME=${ADMIN_USERNAME}
ADMIN_PASSWORD=${ADMIN_PASSWORD}
ADMIN_EMAIL=${ADMIN_EMAIL}

# ── Server / TLS ──────────────────────────────────────────────────────
SERVER_DOMAIN=${SERVER_DOMAIN}
TLS_OPTION=${TLS_OPTION}
HTTP_PORT=${HTTP_PORT}
HTTPS_PORT=${HTTPS_PORT}
MAX_UPLOAD_SIZE=${MAX_UPLOAD_SIZE}

# ── Email Notifications ──────────────────────────────────────────────
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

# ── Source .env for remaining steps ──────────────────────────────────
set -a
source .env
set +a

# ═══════════════════════════════════════════════════════════════════════════════
# Step 4: TLS Certificates
# ═══════════════════════════════════════════════════════════════════════════════
step 4 "TLS certificate setup"

mkdir -p nginx/certs

case "${TLS_OPTION:-1}" in
  1)
    if [[ -f "nginx/certs/selfsigned.crt" && -f "nginx/certs/selfsigned.key" ]]; then
      CERT_EXPIRY=$(openssl x509 -enddate -noout -in nginx/certs/selfsigned.crt 2>/dev/null | cut -d= -f2)
      info "Existing certificate (expires: ${CERT_EXPIRY:-unknown})"
      if ask_yn "Regenerate certificate?" "n"; then
        REGEN=true
      else
        REGEN=false
      fi
    else
      REGEN=true
    fi

    if [[ "$REGEN" == "true" ]]; then
      info "Generating self-signed TLS certificate for ${SERVER_DOMAIN}..."
      SAN="DNS:${SERVER_DOMAIN}"
      if [[ "${SERVER_DOMAIN}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        SAN="IP:${SERVER_DOMAIN}"
      fi
      openssl req -x509 -nodes -days 365 \
        -newkey rsa:2048 \
        -keyout nginx/certs/selfsigned.key \
        -out nginx/certs/selfsigned.crt \
        -subj "/C=US/ST=Local/L=Local/O=VPRP/CN=${SERVER_DOMAIN}" \
        -addext "subjectAltName=${SAN}" \
        2>/dev/null
      chmod 600 nginx/certs/selfsigned.key
      success "Self-signed certificate generated (valid 365 days)"
    else
      success "Using existing certificate"
    fi
    ;;

  2)
    info "Let's Encrypt — ensure ${SERVER_DOMAIN} resolves to this server"
    if ! command -v certbot &>/dev/null; then
      warn "certbot not found — install: sudo apt install certbot python3-certbot-nginx"
    fi
    # Generate temporary self-signed so nginx can start
    if [[ ! -f "nginx/certs/selfsigned.crt" ]]; then
      info "Generating temporary certificate for initial startup..."
      openssl req -x509 -nodes -days 30 -newkey rsa:2048 \
        -keyout nginx/certs/selfsigned.key \
        -out nginx/certs/selfsigned.crt \
        -subj "/CN=${SERVER_DOMAIN}" 2>/dev/null
    fi
    ;;

  3)
    ask CERT_PATH "Path to your certificate (.crt/.pem)" ""
    ask KEY_PATH  "Path to your private key (.key)"       ""
    if [[ -f "$CERT_PATH" && -f "$KEY_PATH" ]]; then
      cp "$CERT_PATH" nginx/certs/selfsigned.crt
      cp "$KEY_PATH"  nginx/certs/selfsigned.key
      chmod 600 nginx/certs/selfsigned.key
      success "Custom certificate installed"
    else
      fail "Certificate file(s) not found — generating self-signed fallback"
      openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout nginx/certs/selfsigned.key \
        -out nginx/certs/selfsigned.crt \
        -subj "/CN=${SERVER_DOMAIN}" 2>/dev/null
      chmod 600 nginx/certs/selfsigned.key
    fi
    ;;

  4)
    warn "TLS disabled — not recommended for production"
    # Still generate a dummy cert so nginx config doesn't break
    if [[ ! -f "nginx/certs/selfsigned.crt" ]]; then
      openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout nginx/certs/selfsigned.key \
        -out nginx/certs/selfsigned.crt \
        -subj "/CN=localhost" 2>/dev/null
    fi
    ;;
esac

# ═══════════════════════════════════════════════════════════════════════════════
# Step 5: Pre-flight checks
# ═══════════════════════════════════════════════════════════════════════════════
step 5 "Pre-flight checks"

# Create required directories
mkdir -p "${BACKUP_DIR:-./backups}" data logs
success "Directories created"

# Check compose files
COMPOSE_FILES="-f docker-compose.yml"
if [[ -f "docker-compose.yml" ]]; then
  success "docker-compose.yml found"
else
  fail "docker-compose.yml not found — cannot continue"
  exit 1
fi
if [[ -f "docker-compose.prod.yml" ]]; then
  COMPOSE_FILES="$COMPOSE_FILES -f docker-compose.prod.yml"
  success "docker-compose.prod.yml found (production overrides)"
fi

# Validate critical .env values
PREFLIGHT_PASS=true
for var in POSTGRES_USER POSTGRES_PASSWORD POSTGRES_DB DATABASE_URL SECRET_KEY; do
  if [[ -z "${!var:-}" ]]; then
    fail "Missing required: $var"
    PREFLIGHT_PASS=false
  fi
done
if [[ "$PREFLIGHT_PASS" == "true" ]]; then
  success "All required environment variables present"
else
  fail "Fix .env and re-run"
  exit 1
fi

# ── Update docker-compose.prod.yml ports if non-standard ─────
HTTP_PORT="${HTTP_PORT:-80}"
HTTPS_PORT="${HTTPS_PORT:-443}"

if [[ "$HTTP_PORT" != "80" || "$HTTPS_PORT" != "443" ]]; then
  info "Updating nginx ports to ${HTTP_PORT}:80 and ${HTTPS_PORT}:443..."
  if [[ -f "docker-compose.prod.yml" ]]; then
    sed -i "s|\"80:80\"|\"${HTTP_PORT}:80\"|g"   docker-compose.prod.yml
    sed -i "s|\"443:443\"|\"${HTTPS_PORT}:443\"|g" docker-compose.prod.yml
    success "Ports updated in docker-compose.prod.yml"
  fi
fi

# Stop existing VPRP containers gracefully (ignore errors)
RUNNING=$(docker ps -q --filter "name=vprp-" 2>/dev/null | wc -l)
if [[ "$RUNNING" -gt 0 ]]; then
  info "Stopping existing VPRP containers..."
  $COMPOSE_CMD $COMPOSE_FILES down 2>/dev/null || true
  success "Previous containers stopped"
else
  info "No existing VPRP containers running"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# Step 6: Build & Start
# ═══════════════════════════════════════════════════════════════════════════════
step 6 "Building and starting containers"

info "Pulling base images..."
$COMPOSE_CMD $COMPOSE_FILES pull --ignore-buildable 2>/dev/null || true

info "Building application image (this may take 1-3 minutes)..."
if ! $COMPOSE_CMD $COMPOSE_FILES build app; then
  fail "Docker build failed. Check the Dockerfile and try again."
  exit 1
fi
echo ""

info "Starting all services..."
if ! $COMPOSE_CMD $COMPOSE_FILES up -d; then
  fail "Failed to start containers"
  echo "  Debug: $COMPOSE_CMD $COMPOSE_FILES logs --tail 30"
  exit 1
fi
echo ""

# ── Wait for health ──────────────────────────────────────────
info "Waiting for services to become healthy..."
MAX_WAIT=120
ELAPSED=0
HEALTHY=false

while [[ $ELAPSED -lt $MAX_WAIT ]]; do
  PG_STATUS=$(docker inspect --format='{{.State.Health.Status}}' vprp-postgres 2>/dev/null || echo "waiting")
  APP_STATE=$(docker inspect --format='{{.State.Status}}' vprp-app 2>/dev/null || echo "waiting")
  APP_RESTART=$(docker inspect --format='{{.RestartCount}}' vprp-app 2>/dev/null || echo "0")

  # Crash-loop detection
  if [[ "$APP_RESTART" -gt 3 ]]; then
    echo ""
    fail "Application is crash-looping (${APP_RESTART} restarts)"
    echo ""
    echo "  Recent logs:"
    $COMPOSE_CMD $COMPOSE_FILES logs --tail 30 app 2>/dev/null || true
    echo ""
    fail "Fix the issue above and re-run deploy.sh"
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
  fail "Services did not become healthy within ${MAX_WAIT}s"
  echo ""
  echo "  Debug commands:"
  echo "    $COMPOSE_CMD $COMPOSE_FILES ps"
  echo "    $COMPOSE_CMD $COMPOSE_FILES logs --tail 80 app"
  echo "    $COMPOSE_CMD $COMPOSE_FILES logs --tail 30 postgres"
  exit 1
fi

echo ""
echo -e "  ${BOLD}Service Status:${NC}"
success "PostgreSQL:   healthy"
success "Application:  running (HTTP 200)"
NGINX_STATUS=$(docker inspect --format='{{.State.Status}}' vprp-nginx 2>/dev/null || echo "not found")
[[ "$NGINX_STATUS" == "running" ]] && success "Nginx:        running" || warn "Nginx:        $NGINX_STATUS"

# ═══════════════════════════════════════════════════════════════════════════════
# Step 7: Database Migrations
# ═══════════════════════════════════════════════════════════════════════════════
step 7 "Running database migrations"

info "Applying Alembic migrations..."
MIGRATION_OUTPUT=$(docker exec vprp-app alembic -c /app/alembic.ini upgrade head 2>&1) || true

if echo "$MIGRATION_OUTPUT" | grep -qiE "error|traceback"; then
  warn "Migration had warnings:"
  echo "$MIGRATION_OUTPUT" | tail -5
else
  success "Migrations applied"
fi

ALEMBIC_REV=$(docker exec vprp-app alembic -c /app/alembic.ini current 2>&1 | grep -oP '[a-f0-9]{12}' | head -1 || echo "unknown")
success "Alembic revision: ${ALEMBIC_REV}"

# Verify key tables
TABLE_CHECK=$(docker exec vprp-app python -c "
from app.models.database import engine
from sqlalchemy import inspect
tables = inspect(engine).get_table_names()
required = ['findings', 'assets', 'asset_groups', 'users', 'scan_uploads']
missing = [t for t in required if t not in tables]
print(f'MISSING:{chr(44).join(missing)}' if missing else f'OK:{len(tables)}')
" 2>&1) || true

if [[ "$TABLE_CHECK" == OK* ]]; then
  success "Database schema verified (${TABLE_CHECK#OK:} tables)"
elif [[ "$TABLE_CHECK" == MISSING* ]]; then
  warn "Missing tables: ${TABLE_CHECK#MISSING:}"
else
  warn "Schema check: $TABLE_CHECK"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# Step 8: Create Admin User
# ═══════════════════════════════════════════════════════════════════════════════
step 8 "Creating initial admin user"

ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-}"

if [[ -z "$ADMIN_PASSWORD" ]]; then
  warn "No ADMIN_PASSWORD in .env — skipping admin creation"
  warn "Create one manually via the Administration page"
else
  # Escape single quotes in password for Python
  ESCAPED_PW=$(echo "$ADMIN_PASSWORD" | sed "s/'/\\\\'/g")

  ADMIN_RESULT=$(docker exec vprp-app python -c "
import sys
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
    *EXISTS*)  info "Admin user '${ADMIN_USERNAME}' already exists" ;;
    *CREATED*) success "Admin user '${ADMIN_USERNAME}' created" ;;
    *ERROR*)   warn "Could not create admin: ${ADMIN_RESULT#*ERROR:}" ;;
    *)         warn "Admin creation result: $ADMIN_RESULT" ;;
  esac
fi

# ═══════════════════════════════════════════════════════════════════════════════
# Step 9: Let's Encrypt (if selected)
# ═══════════════════════════════════════════════════════════════════════════════
if [[ "${TLS_OPTION:-1}" == "2" ]]; then
  step 9 "Let's Encrypt certificate"

  if command -v certbot &>/dev/null; then
    ask CERTBOT_EMAIL "Email for Let's Encrypt" "${ADMIN_EMAIL:-}"
    info "Requesting certificate for ${SERVER_DOMAIN}..."
    sudo certbot certonly --standalone \
      --preferred-challenges http \
      -d "${SERVER_DOMAIN}" \
      --email "${CERTBOT_EMAIL}" \
      --agree-tos --non-interactive 2>&1 | tail -5 || true

    LE_CERT="/etc/letsencrypt/live/${SERVER_DOMAIN}/fullchain.pem"
    LE_KEY="/etc/letsencrypt/live/${SERVER_DOMAIN}/privkey.pem"
    if [[ -f "$LE_CERT" && -f "$LE_KEY" ]]; then
      sudo cp "$LE_CERT" nginx/certs/selfsigned.crt
      sudo cp "$LE_KEY"  nginx/certs/selfsigned.key
      sudo chmod 600 nginx/certs/selfsigned.key
      $COMPOSE_CMD $COMPOSE_FILES restart nginx
      success "Let's Encrypt certificate installed and nginx restarted"
    else
      warn "Certbot did not produce certificates — using self-signed fallback"
    fi
  else
    warn "certbot not installed — run manually:"
    echo "    sudo apt install certbot"
    echo "    sudo certbot certonly --standalone -d ${SERVER_DOMAIN}"
  fi
fi

# ═══════════════════════════════════════════════════════════════════════════════
# Step 10: Final Summary
# ═══════════════════════════════════════════════════════════════════════════════
echo ""
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║                                                                  ║${NC}"
echo -e "${GREEN}${BOLD}║           🛡️  VPRP Deployed Successfully!                         ║${NC}"
echo -e "${GREEN}${BOLD}║                                                                  ║${NC}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════════════╝${NC}"

# ── Access URLs ──────────────────────────────────────────────
echo ""
echo -e "  ${BOLD}Access URLs${NC}"
echo -e "  ─────────────────────────────────────────────────"
HTTP_PORT="${HTTP_PORT:-80}"
HTTPS_PORT="${HTTPS_PORT:-443}"

case "${TLS_OPTION:-1}" in
  1|2|3)
    if [[ "$HTTPS_PORT" == "443" ]]; then
      echo -e "    HTTPS:  ${CYAN}https://${SERVER_DOMAIN}/${NC}"
    else
      echo -e "    HTTPS:  ${CYAN}https://${SERVER_DOMAIN}:${HTTPS_PORT}/${NC}"
    fi
    if [[ "$HTTP_PORT" == "80" ]]; then
      echo -e "    HTTP:   ${CYAN}http://${SERVER_DOMAIN}/${NC}  (redirects to HTTPS)"
    else
      echo -e "    HTTP:   ${CYAN}http://${SERVER_DOMAIN}:${HTTP_PORT}/${NC}  (redirects to HTTPS)"
    fi
    ;;
  4)
    if [[ "$HTTP_PORT" == "80" ]]; then
      echo -e "    HTTP:   ${CYAN}http://${SERVER_DOMAIN}/${NC}"
    else
      echo -e "    HTTP:   ${CYAN}http://${SERVER_DOMAIN}:${HTTP_PORT}/${NC}"
    fi
    ;;
esac

# ── Credentials ──────────────────────────────────────────────
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
  echo -e "    Password:  ${CYAN}${MASKED}${NC}  (see .env for full value)"
fi

# ── Container Status ─────────────────────────────────────────
echo ""
echo -e "  ${BOLD}Container Status${NC}"
echo -e "  ─────────────────────────────────────────────────"
$COMPOSE_CMD $COMPOSE_FILES ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null \
  || $COMPOSE_CMD $COMPOSE_FILES ps

# ── Useful Commands ──────────────────────────────────────────
echo ""
echo -e "  ${BOLD}Useful Commands${NC}"
echo -e "  ─────────────────────────────────────────────────"
echo -e "    View logs:         ${CYAN}$COMPOSE_CMD $COMPOSE_FILES logs -f app${NC}"
echo -e "    Stop everything:   ${CYAN}$COMPOSE_CMD $COMPOSE_FILES down${NC}"
echo -e "    Restart app:       ${CYAN}$COMPOSE_CMD $COMPOSE_FILES restart app${NC}"
echo -e "    Rebuild & deploy:  ${CYAN}$COMPOSE_CMD $COMPOSE_FILES up -d --build app${NC}"
echo -e "    Database backup:   ${CYAN}docker exec vprp-postgres pg_dump -U ${POSTGRES_USER} ${POSTGRES_DB} > backup.sql${NC}"
echo -e "    Alembic status:    ${CYAN}docker exec vprp-app alembic -c /app/alembic.ini current${NC}"
echo -e "    App shell:         ${CYAN}docker exec -it vprp-app /bin/bash${NC}"
echo -e "    DB shell:          ${CYAN}docker exec -it vprp-postgres psql -U ${POSTGRES_USER} ${POSTGRES_DB}${NC}"

# ── File Locations ───────────────────────────────────────────
echo ""
echo -e "  ${BOLD}File Locations${NC}"
echo -e "  ─────────────────────────────────────────────────"
echo -e "    Project:       ${CYAN}$(pwd)${NC}"
echo -e "    Environment:   ${CYAN}$(pwd)/.env${NC}"
echo -e "    Backups:       ${CYAN}$(pwd)/${BACKUP_DIR:-./backups}${NC}"
echo -e "    TLS certs:     ${CYAN}$(pwd)/nginx/certs/${NC}"

# ── Warnings ─────────────────────────────────────────────────
echo ""
if [[ "${TLS_OPTION:-1}" == "1" ]]; then
  warn "Self-signed certificate — browser will show a security warning (expected)."
  echo -e "    For production, use Let's Encrypt (option 2) or a CA-signed certificate."
fi
if [[ "${APP_ENV:-}" != "production" ]]; then
  warn "Running in '${APP_ENV}' mode."
fi

echo ""
success "Deployment finished at $(date -u +'%Y-%m-%d %H:%M:%S UTC')"
echo ""

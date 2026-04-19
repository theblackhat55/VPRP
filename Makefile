# ============================================================
# VPRP Platform — Developer Commands
# ============================================================

.PHONY: help dev dev-d dev-down prod prod-down down logs logs-app \
        rebuild test test-cov lint format db-shell backup restore deploy

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

# ── Development (Dev VM) ─────────────────────────────────
dev: ## Start dev mode (foreground, live reload)
	docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build

dev-d: ## Start dev mode (detached)
	docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build -d

dev-down: ## Stop dev services
	docker compose -f docker-compose.yml -f docker-compose.dev.yml down

# ── Production ───────────────────────────────────────────
prod: ## Start production mode (detached)
	docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build

prod-down: ## Stop production services
	docker compose -f docker-compose.yml -f docker-compose.prod.yml down

# ── Common ───────────────────────────────────────────────
down: ## Stop all services
	docker compose down

logs: ## Tail all logs
	docker compose logs -f

logs-app: ## Tail app logs only
	docker compose logs -f app

rebuild: ## Force rebuild all containers
	docker compose build --no-cache

# ── Testing ──────────────────────────────────────────────
test: ## Run all tests
	docker compose -f docker-compose.yml -f docker-compose.dev.yml \
		exec app pytest tests/ -v --tb=short

test-cov: ## Run tests with coverage
	docker compose -f docker-compose.yml -f docker-compose.dev.yml \
		exec app pytest tests/ -v --cov=app --cov-report=term

lint: ## Run linter
	docker compose -f docker-compose.yml -f docker-compose.dev.yml \
		exec app ruff check app/ tests/

format: ## Auto-format code
	docker compose -f docker-compose.yml -f docker-compose.dev.yml \
		exec app ruff format app/ tests/

# ── Database ─────────────────────────────────────────────
db-shell: ## Open PostgreSQL shell
	docker compose exec postgres psql -U $${POSTGRES_USER:-vprp_user} -d $${POSTGRES_DB:-vprp}

# ── Backup & Restore ─────────────────────────────────────
backup: ## Backup database
	bash scripts/backup.sh

restore: ## Restore database from latest backup
	bash scripts/restore.sh

# ── Deployment ───────────────────────────────────────────
deploy: ## Pull latest from GitHub and redeploy (production)
	bash scripts/deploy.sh

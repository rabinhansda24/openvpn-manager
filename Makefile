# OpenVPN Manager - Development Makefile

.PHONY: help install install-dev run run-dev test test-cov clean lint format setup-dev docker-build docker-up docker-down init-db create-admin backup restore

# Default target
help:
	@echo "OpenVPN Manager Development Commands"
	@echo "=================================="
	@echo ""
	@echo "Development:"
	@echo "  install      Install production dependencies"
	@echo "  install-dev  Install development dependencies"
	@echo "  setup-dev    Set up development environment"
	@echo "  run          Run production server"
	@echo "  run-dev      Run development server"
	@echo "  run-worker   Run Celery worker"
	@echo "  run-beat     Run Celery beat scheduler"
	@echo ""
	@echo "Database:"
	@echo "  init-db      Initialize database"
	@echo "  create-admin Create admin user"
	@echo "  migrate      Run database migrations"
	@echo "  upgrade      Upgrade database to latest version"
	@echo ""
	@echo "Testing:"
	@echo "  test         Run test suite"
	@echo "  test-cov     Run tests with coverage"
	@echo "  test-unit    Run unit tests only"
	@echo "  test-api     Run API tests only"
	@echo ""
	@echo "Code Quality:"
	@echo "  lint         Run linting checks"
	@echo "  format       Format code with black"
	@echo "  type-check   Run type checking with mypy"
	@echo "  security     Run security checks"
	@echo ""
	@echo "Docker:"
	@echo "  docker-build Build Docker images"
	@echo "  docker-up    Start Docker services"
	@echo "  docker-down  Stop Docker services"
	@echo "  docker-logs  View Docker logs"
	@echo ""
	@echo "Operations:"
	@echo "  backup       Create system backup"
	@echo "  restore      Restore from backup"
	@echo "  clean        Clean temporary files"
	@echo "  clean-all    Clean everything including containers"

# Python and dependency management
PYTHON := python3
PIP := pip
UV := uv

# Check if UV is available
UV_AVAILABLE := $(shell command -v uv 2> /dev/null)

# Development setup
setup-dev:
	@echo "Setting up development environment..."
ifdef UV_AVAILABLE
	$(UV) venv
	$(UV) pip install -r requirements.txt
	$(UV) pip install pytest pytest-flask pytest-cov black flake8 mypy bandit
else
	$(PYTHON) -m venv venv
	. venv/bin/activate && $(PIP) install -r requirements.txt
	. venv/bin/activate && $(PIP) install pytest pytest-flask pytest-cov black flake8 mypy bandit
endif
	@echo "Development environment ready!"
	@echo "Activate with: source venv/bin/activate (Linux/Mac) or venv\\Scripts\\activate (Windows)"

# Installation targets
install:
ifdef UV_AVAILABLE
	$(UV) pip install -r requirements.txt
else
	$(PIP) install -r requirements.txt
endif

install-dev:
ifdef UV_AVAILABLE
	$(UV) pip install -r requirements.txt
	$(UV) pip install pytest pytest-flask pytest-cov black flake8 mypy bandit pre-commit
else
	$(PIP) install -r requirements.txt
	$(PIP) install pytest pytest-flask pytest-cov black flake8 mypy bandit pre-commit
endif

# Running the application
run:
	$(PYTHON) app.py

run-dev:
	FLASK_ENV=development FLASK_DEBUG=True $(PYTHON) app.py

run-worker:
	celery -A app.celery worker --loglevel=info

run-beat:
	celery -A app.celery beat --loglevel=info

# Database operations
init-db:
	flask init-db

create-admin:
	flask create-admin

migrate:
	flask db migrate

upgrade:
	flask db upgrade

# Testing
test:
	pytest tests/ -v

test-cov:
	pytest tests/ --cov=app --cov-report=html --cov-report=term-missing

test-unit:
	pytest tests/test_models.py tests/test_utils.py -v

test-api:
	pytest tests/test_api.py -v

# Code quality
lint:
	flake8 app/ tests/
	black --check app/ tests/

format:
	black app/ tests/

type-check:
	mypy app/

security:
	bandit -r app/

# Docker operations
docker-build:
	docker-compose build

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

docker-logs:
	docker-compose logs -f

docker-shell:
	docker-compose exec web bash

# Backup and restore
backup:
	@echo "Creating backup..."
	docker-compose exec web python -c "from app.services.backup_service import BackupService; BackupService().create_backup()"

restore:
	@echo "Available backups:"
	docker-compose exec web python -c "from app.services.backup_service import BackupService; print([b['name'] for b in BackupService().list_backups()])"
	@read -p "Enter backup name to restore: " backup_name; \
	docker-compose exec web python -c "from app.services.backup_service import BackupService; BackupService().restore_backup('$$backup_name')"

# Cleanup
clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type f -name "*.coverage" -delete
	rm -rf htmlcov/
	rm -rf .pytest_cache/
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/

clean-all: clean
	docker-compose down -v
	docker system prune -f

# Development helpers
check-deps:
	$(PIP) list --outdated

update-deps:
	$(PIP) list --outdated --format=freeze | grep -v '^\-e' | cut -d = -f 1 | xargs -n1 $(PIP) install -U

install-hooks:
	pre-commit install

# Documentation
docs:
	@echo "Generating API documentation..."
	@# Add documentation generation commands here

# Quick development start
dev-start: setup-dev init-db create-admin
	@echo "Development environment is ready!"
	@echo "Run 'make run-dev' to start the development server"

# Production deployment helpers
prod-check:
	@echo "Running production readiness checks..."
	@echo "Checking environment variables..."
	@python -c "import os; required=['SECRET_KEY', 'DATABASE_URL']; missing=[k for k in required if not os.getenv(k)]; print('Missing required env vars:', missing) if missing else print('Environment OK')"
	@echo "Checking database connection..."
	@python -c "from app import create_app, db; app = create_app(); app.app_context().push(); db.create_all(); print('Database OK')"
	@echo "Running security checks..."
	@make security

deploy-prod: prod-check
	@echo "Deploying to production..."
	docker-compose -f docker-compose.yml up -d --build

# Monitoring and logs
logs-app:
	docker-compose logs -f web

logs-worker:
	docker-compose logs -f worker

logs-db:
	docker-compose logs -f db

logs-redis:
	docker-compose logs -f redis

# Health checks
health-check:
	@curl -f http://localhost:5000/health || echo "Health check failed"

# Certificate management
generate-certs:
	@echo "Generating development certificates..."
	mkdir -p certs
	openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"

# Environment setup
env-template:
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "Created .env from template. Please edit with your configuration."; \
	else \
		echo ".env already exists"; \
	fi

# Complete setup for new developers
first-time-setup: env-template setup-dev init-db create-admin install-hooks
	@echo ""
	@echo "🎉 First-time setup complete!"
	@echo ""
	@echo "Next steps:"
	@echo "1. Edit .env file with your configuration"
	@echo "2. Run 'make run-dev' to start development server"
	@echo "3. Open http://localhost:5000 in your browser"
	@echo "4. Login with admin/admin (change password immediately)"
	@echo ""
	@echo "For more commands, run 'make help'"

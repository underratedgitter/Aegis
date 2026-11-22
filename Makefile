.PHONY: start up down logs backup test test-cov lint format typecheck chaos e2e-reliability clean help

# Default target
help:
	@echo "Aegis SRE Copilot - Available Commands:"
	@echo ""
	@echo "  make start     - Build and start all services"
	@echo "  make up        - Start services without building"
	@echo "  make down      - Stop all services"
	@echo "  make logs      - View logs for control, checkout, and inventory"
	@echo "  make backup    - Save a consistent copy of the incident database to ./backups"
	@echo "  make test      - Run tests"
	@echo "  make test-cov  - Run tests with a coverage report (terminal and htmlcov/)"
	@echo "  make lint      - Run linter"
	@echo "  make format    - Format code"
	@echo "  make typecheck - Run type checker"
	@echo "  make chaos     - Inject chaos into inventory service"
	@echo "  make e2e-reliability - Fault-injection proof on a separate Compose project (E2E_PROJECT, E2E_PORT_BASE)"
	@echo "  make clean     - Remove temporary files"
	@echo ""

start:
	./scripts/start.sh

up:
	docker compose up --build

down:
	docker compose down

logs:
	docker compose logs -f control checkout inventory

backup:
	@mkdir -p backups
	@name=aegis-$$(date -u +%Y%m%dT%H%M%SZ).db; \
	docker compose exec -T control python -m aegis.backup_main /data/backups/$$name >/dev/null && \
	docker compose cp control:/data/backups/$$name backups/$$name && \
	docker compose exec -T control rm /data/backups/$$name && \
	echo "Backup written to backups/$$name"

test:
	python -m pytest -v --tb=short

test-cov:
	python -m pytest -v --cov=aegis --cov-report=html --cov-report=term

lint:
	ruff check aegis tests scripts

format:
	ruff format aegis tests scripts

typecheck:
	mypy aegis --ignore-missing-imports

chaos:
	python scripts/chaos.py --service inventory --fault dependency --duration 60

e2e-reliability:
	./scripts/e2e_reliability.sh

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage
	rm -rf dist build *.egg-info

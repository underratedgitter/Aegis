.PHONY: start up down logs test lint format typecheck chaos clean help

# Default target
help:
	@echo "Aegis SRE Copilot - Available Commands:"
	@echo ""
	@echo "  make start     - Build and start all services"
	@echo "  make up        - Start services without building"
	@echo "  make down      - Stop all services"
	@echo "  make logs      - View logs for control, checkout, and inventory"
	@echo "  make test      - Run tests"
	@echo "  make lint      - Run linter"
	@echo "  make format    - Format code"
	@echo "  make typecheck - Run type checker"
	@echo "  make chaos     - Inject chaos into inventory service"
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

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .pytest_cache .ruff_cache mypy_cache htmlcov .coverage
	rm -rf dist build *.egg-info

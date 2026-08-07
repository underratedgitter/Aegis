.PHONY: up down logs test lint chaos

up:
	docker compose up --build

down:
	docker compose down

logs:
	docker compose logs -f control checkout inventory

test:
	python -m pytest -q

lint:
	ruff check aegis tests scripts

chaos:
	python scripts/chaos.py --service inventory --fault dependency --duration 60


.PHONY: setup up down logs test lint security-check reset-demo

setup:
	@echo "Setting up AegisVault development environment..."
	python3 -m venv apps/api/.venv
	./apps/api/.venv/bin/pip install --upgrade pip
	./apps/api/.venv/bin/pip install -r apps/api/requirements.txt
	npm install
	@echo "✓ Environment setup complete."

up:
	docker compose up --build -d

down:
	docker compose down

logs:
	docker compose logs -f

test:
	@echo "Running backend unit and integration test suite..."
	PYTHONPATH=. ./apps/api/.venv/bin/pytest tests/test_crypto_and_api.py tests/test_api_integration.py
	@echo "Running frontend component and SSR test suite..."
	npm test

lint:
	npm run lint

security-check:
	@echo "Scanning codebase for hardcoded secrets and dependency issues..."
	PYTHONPATH=. ./apps/api/.venv/bin/pytest tests/test_crypto_and_api.py -k test_scanner_detects_credentials_safely

reset-demo:
	@echo "Resetting local demo database volumes..."
	docker compose down -v
	docker compose up -d postgres redis
	@sleep 3
	docker compose restart api

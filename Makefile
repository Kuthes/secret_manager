.PHONY: setup up down logs test test-all test-frontend lint security-check reset-demo build-sdks

setup:
	@echo "Setting up AegisVault Fortress development environment..."
	python3 -m venv apps/api/.venv
	./apps/api/.venv/bin/pip install --upgrade pip
	./apps/api/.venv/bin/pip install -r apps/api/requirements.txt
	npm install
	@echo "✓ Fortress environment setup complete."

up:
	docker-compose -f infrastructure/docker-compose.yml up --build -d

down:
	docker-compose -f infrastructure/docker-compose.yml down

logs:
	docker-compose -f infrastructure/docker-compose.yml logs -f

test:
	@echo "Running complete Fortress security and integration test suite..."
	PYTHONPATH=.:./sdks/python/src:./sdk/python ./apps/api/.venv/bin/pytest tests/

test-frontend:
	@echo "Running frontend component and SSR test suite..."
	npm test

test-all: test test-frontend

build-sdks:
	@echo "Building Go CLI (av) and Go Agent..."
	cd sdks/go && go build -o ../../bin/av ./cmd/av && go build -o ../../bin/agent ./cmd/agent
	@echo "Building Python SDK..."
	cd sdks/python && pip install -e .

lint:
	npm run lint

security-check:
	@echo "Scanning codebase for hardcoded secrets and invariant checks..."
	PYTHONPATH=.:./sdks/python/src ./apps/api/.venv/bin/pytest tests/security/

reset-demo:
	@echo "Resetting local demo database volumes..."
	docker-compose -f infrastructure/docker-compose.yml down -v
	docker-compose -f infrastructure/docker-compose.yml up -d postgres redis
	@sleep 3
	docker-compose -f infrastructure/docker-compose.yml restart api

# File Structure Reorganization Plan

## Objective
Reorganize the entire repository into the clean, monorepo-style fortress structure requested:

1. **`apps/`**:
   - `apps/api/`: Python FastAPI backend (`app/`, `requirements.txt`, `pyproject.toml`)
   - `apps/web/`: Next.js 15 Web Console (`src/app/`, `src/components/`, `src/hooks/`, `src/lib/`, `src/styles/`, `public/`, `next.config.ts`, `package.json`, etc.)
   - `apps/worker/`: Celery asynchronous worker (`celery_app.py`, `tasks.py`)
2. **`sdks/`**:
   - `sdks/python/`: Python SDK (`aegisvault/`, `pyproject.toml`)
   - `sdks/go/`: Go CLI (`cmd/av/`) & Daemon Agent (`cmd/agent/`), `go.mod`
   - `sdks/js/`: TypeScript/JavaScript SDK (`src/`, `package.json`, `tsconfig.json`)
3. **`infrastructure/`**:
   - `infrastructure/docker/`: `Dockerfile.api`, `Dockerfile.web`, `Dockerfile.worker`
   - `infrastructure/docker-compose.yml`, `infrastructure/docker-compose.production.yml`, `infrastructure/docker-compose.staging.yml`
   - `infrastructure/kubernetes/`: `deployment.yaml`, `services.yaml`, `configmaps.yaml`
   - `infrastructure/scripts/`: `install_linux.sh`, `aegisvault_ctl.sh`, `backup.sh`, `restore.sh`, etc.
   - `infrastructure/drizzle/`: Schema & migration definitions
4. **`tests/`**:
   - `tests/security/`, `tests/disaster_recovery/`, `tests/integration/`
5. **`config/`**:
   - `.env.example`, `.env.staging.example`, `eslint.config.mjs`, `tsconfig.json`
6. **`.github/`**:
   - `workflows/test.yml`, `workflows/security-scan.yml`, `workflows/deploy.yml`, `CONTRIBUTING.md`
7. **Root files**:
   - `Makefile`, `package.json`, `turbo.json`, `README.md`, `CHANGELOG.md`, `LICENSE`, `SECURITY.md`

## Safety & Invariant Guarantees
- Ensure all 150 automated Python pytest security suites pass.
- Ensure frontend builds and linting continue passing.
- Provide backward-compatible references so existing tools and deployment targets remain intact.

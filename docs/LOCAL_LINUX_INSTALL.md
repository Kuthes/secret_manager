# AegisVault Local Linux Installation & Development Guide

This guide covers setting up AegisVault locally on Linux (Ubuntu, Debian, Fedora, Arch, etc.).

You can run AegisVault locally via **Docker Compose** (recommended, zero-dependency setup) or **Native Linux Installation**.

---

## Method 1: Docker Compose (Quickest & Recommended)

### 1. Prerequisites
Ensure Docker and Docker Compose are installed:
```bash
sudo apt update
sudo apt install -y docker.io docker-compose-v2
sudo usermod -aG docker $USER
newgrp docker
```

### 2. Start AegisVault
From the repository root:
```bash
docker compose up --build
```

This launches:
- **Web Dashboard**: [http://localhost:3000](http://localhost:3000)
- **API & Swagger Docs**: [http://localhost:8000/api/v1/docs](http://localhost:8000/api/v1/docs)
- **Mailpit Email UI**: [http://localhost:8025](http://localhost:8025)
- **PostgreSQL 16**: `localhost:5432`
- **Redis 7**: `localhost:6379`

Demo credentials (when `DEMO_MODE=true`):
- **Email**: `demo@aegisvault.local`
- **Password**: `AegisDemo2026!`

---

## Method 2: Native Linux Installation (Bare Metal / Development)

### 1. System Package Requirements

#### Ubuntu / Debian:
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv postgresql postgresql-contrib redis-server build-essential libpq-dev curl git
```

#### Fedora / RHEL:
```bash
sudo dnf install -y python3 python3-pip postgresql-server postgresql-contrib redis gcc postgresql-devel curl git
```

#### Arch Linux:
```bash
sudo pacman -S python python-pip postgresql redis base-devel postgresql-libs curl git nodejs npm
```

---

### 2. Configure Local PostgreSQL & Redis

#### Start and Enable Redis:
```bash
sudo systemctl enable --now redis-server || sudo systemctl enable --now redis
```

#### Setup PostgreSQL Database and User:
```bash
sudo -u postgres psql -c "CREATE USER aegisvault WITH PASSWORD 'aegisvault_dev_pass' SUPERUSER;"
sudo -u postgres psql -c "CREATE DATABASE aegisvault OWNER aegisvault;"
```

---

### 3. Setup Python Backend Environment

```bash
# 1. Navigate to API directory
cd apps/api

# 2. Create Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt
cd ../..
```

#### Create `.env` for Local Development:
```bash
cat << 'ENV' > .env
ENVIRONMENT=development
DEBUG=true
DEMO_MODE=true

DATABASE_URL=postgresql+asyncpg://aegisvault:aegisvault_dev_pass@localhost:5432/aegisvault
REDIS_URL=redis://localhost:6379/0

MASTER_ENCRYPTION_KEY=TESTONLY_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
MEK_ID=mek-local-v1
SECRET_KEY=TESTONLY_insecure_jwt_secret_key_for_development
API_V1_STR=/api/v1

NEXT_PUBLIC_API_URL=http://localhost:8000/api/v1
ENV
```

---

### 4. Setup Node.js Frontend

Ensure Node.js (>= 20.x or 22.x) is installed:
```bash
# Install dependencies
npm install
```

---

### 5. Running the Services

Open separate terminal tabs or use a process manager (e.g. `tmux` / `foreman`):

#### Terminal 1: Backend API
```bash
source apps/api/.venv/bin/activate
PYTHONPATH=. uvicorn apps.api.app.main:app --host 0.0.0.0 --port 8000 --reload
```

#### Terminal 2: Celery Background Worker
```bash
source apps/api/.venv/bin/activate
PYTHONPATH=. celery -A apps.worker.celery_app worker --loglevel=info
```

#### Terminal 3: Celery Beat Scheduler
```bash
source apps/api/.venv/bin/activate
PYTHONPATH=. celery -A apps.worker.celery_app beat --loglevel=info
```

#### Terminal 4: Frontend Web UI
```bash
npm run dev
```

---

## 6. Running Security & Unit Test Suite

To verify your local installation, execute the full test suite:
```bash
PYTHONPATH=. apps/api/.venv/bin/pytest tests/
```
All **105 tests** should pass.

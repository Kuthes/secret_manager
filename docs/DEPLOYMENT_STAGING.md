# AegisVault Staging Deployment Guide

This guide walks you through deploying AegisVault in a Staging environment using Docker Compose.

---

## 1. Prerequisites
- **Docker Engine** 24.0+ and **Docker Compose** v2.20+
- **OpenSSL** (for generating high-entropy cryptographic keys)
- Network ports: `3000` (Next.js Web UI), `8000` (FastAPI REST API)

---

## 2. Step-by-Step Staging Setup

### Step 2.1: Prepare Staging Configuration
Copy the staging example template:
```bash
cp .env.staging.example .env.staging
```

### Step 2.2: Generate Cryptographic Keys
Generate strong random keys and populate `.env.staging`:

```bash
# 1. Generate 32-byte Master Encryption Key (MEK) for AES-256-GCM
openssl rand -base64 32

# 2. Generate 64-char JWT Secret Key
openssl rand -hex 32

# 3. Generate Database Password
openssl rand -base64 24
```

Update `.env.staging`:
```ini
ENVIRONMENT=staging
DEMO_MODE=false
POSTGRES_USER=aegisvault_staging
POSTGRES_PASSWORD=<generated_db_password>
POSTGRES_DB=aegisvault_staging
DATABASE_URL=postgresql+asyncpg://aegisvault_staging:<generated_db_password>@postgres:5432/aegisvault_staging
REDIS_URL=redis://redis:6379/0

MASTER_ENCRYPTION_KEY=<generated_base64_mek>
MEK_ID=mek-staging-v1
SECRET_KEY=<generated_hex_jwt_key>

NEXT_PUBLIC_API_URL=http://<staging_host_or_ip>:8000/api/v1
```

---

## 3. Build & Launch Staging Containers

Build the production Docker images and start all services in detached mode:

```bash
docker compose -f docker-compose.staging.yml --env-file .env.staging up -d --build
```

### Check Container Status:
```bash
docker compose -f docker-compose.staging.yml ps
```

All 6 services should be running:
1. `aegisvault-staging-postgres` (Postgres 16)
2. `aegisvault-staging-redis` (Redis 7)
3. `aegisvault-staging-api` (FastAPI Backend on port 8000)
4. `aegisvault-staging-worker` (Celery background worker)
5. `aegisvault-staging-scheduler` (Celery Beat periodic scheduler)
6. `aegisvault-staging-web` (Next.js Frontend on port 3000)

---

## 4. Post-Deployment Verification

### 1. API Health Check
```bash
curl -i http://localhost:8000/api/v1/health
```
Expected response: `HTTP/1.1 200 OK` with status `healthy`.

### 2. View Real-time Application Logs
```bash
docker compose -f docker-compose.staging.yml logs -f api
```

### 3. Access Web Dashboard
Open your browser and navigate to:
`http://<staging-server-ip>:3000`

---

## 5. Maintenance & Upgrades

### Stopping Services:
```bash
docker compose -f docker-compose.staging.yml down
```

### Running Automated Staging Backup:
```bash
BACKUP_DIR=/var/backups/staging DB_HOST=localhost DB_PORT=5432 DB_NAME=aegisvault_staging ./scripts/backup.sh
```

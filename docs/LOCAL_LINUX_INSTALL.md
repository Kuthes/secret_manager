# AegisVault Local Linux Installation & Development Guide

This guide covers setting up and running AegisVault locally on Linux (Ubuntu, Debian, Fedora, RHEL, Rocky, Arch, etc.) — either via **Native Linux Installation (Zero Docker)** or **Docker Compose**.

For a full comparative architecture guide, see [docs/DEPLOYMENT_OPTIONS.md](DEPLOYMENT_OPTIONS.md).

---

## Method 1: Native Linux Bare-Metal Installation (Zero Docker, Zero K8s)

### 1. Automated One-Command Installer

Run the automated installer from the repository root:

```bash
# Clone the repository
git clone git@github.com:Kuthes/secret_manager.git aegisvault
cd aegisvault

# Run the automated installer
sudo ./scripts/install_linux.sh
```

This automated script:
1. Installs system packages: Python 3.12+, PostgreSQL 16, Redis 7, Node.js 20+, and build headers.
2. Starts and provisions PostgreSQL database `aegisvault` and Redis server.
3. Sets up Python virtual environment (`apps/api/.venv`) and installs dependencies.
4. Builds the Next.js production frontend assets.
5. Generates a production `.env` configuration file with cryptographically secure random keys.

---

### 2. Service Management with `aegisvault-ctl`

AegisVault includes a built-in process controller (`scripts/aegisvault_ctl.sh`):

```bash
# Start all services in the background (API, Celery Worker, Celery Beat, Web Console)
./scripts/aegisvault_ctl.sh start

# Check service status, memory usage, and health checks
./scripts/aegisvault_ctl.sh status

# Stream live unified logs
./scripts/aegisvault_ctl.sh logs

# Stop all running services
./scripts/aegisvault_ctl.sh stop
```

---

### 3. Native Local Development Mode

To run with live hot-reloading for local code changes:

```bash
./scripts/aegisvault_ctl.sh dev
```

---

### 4. Production Systemd Service Units

To run AegisVault as managed Linux system services that start automatically on boot:

```bash
# Install and enable systemd units
sudo ./scripts/aegisvault_ctl.sh systemd install

# Manage via standard systemctl
sudo systemctl start aegisvault.target
sudo systemctl status aegisvault.target
sudo systemctl restart aegisvault.target
```

---

## Method 2: Docker Compose (Single-Command Containerized Setup)

```bash
# Copy environment configuration
cp .env.example .env

# Launch production compose stack
docker compose -f docker-compose.production.yml up --build -d
```

---

## Verifying the Installation

Execute the test suite to verify cryptographic and tenant isolation invariants:

```bash
PYTHONPATH=.:sdk/python pytest tests/ -v
```
All **150 tests** should pass.

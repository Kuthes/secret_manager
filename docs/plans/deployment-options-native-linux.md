# Implementation Plan: Deployment Options & Native Linux Bare-Metal Deployment

This plan defines the architecture, tooling, and automation to provide comprehensive deployment options for AegisVault, with a first-class **Native Linux Bare-Metal / Local Installation (without Docker and without Kubernetes)** alongside existing container and orchestration options.

---

## 1. Goal Description

AegisVault currently provides Docker Compose and Kubernetes manifests. Many enterprise environments, air-gapped systems, secure government enclaves, and minimalist developer machines require running directly on bare-metal Linux (Ubuntu, Debian, RHEL, Fedora, Arch) or dedicated virtual machines using `systemd` and native operating system packages without the overhead, privilege requirements, or attack surface of Docker and Kubernetes.

This implementation adds:
1. **Automated Linux Provisioning Script (`scripts/install_linux.sh`)**: One-command dependency installation (Python 3.12, PostgreSQL 16, Redis 7, Node.js, Go), database/user creation, Python venv, and binary builds.
2. **Systemd Service Suite (`deploy/systemd/`)**: Production-grade systemd units for API, Celery Worker, Celery Beat, and Next.js Web Console, unified under `aegisvault.target`.
3. **Unified Process Controller (`scripts/aegisvault_ctl.sh`)**: Local management CLI (`start`, `stop`, `status`, `restart`, `logs`, `dev`) supporting both systemd and direct process management.
4. **Nginx Reverse Proxy Configuration (`deploy/nginx/aegisvault.conf`)**: Production reverse proxy with TLS, security headers, rate limiting, and WebSocket proxying.
5. **Deployment Options Guide (`docs/DEPLOYMENT_OPTIONS.md`)**: Comprehensive comparative guide comparing Docker Compose, Native Linux Systemd, Local Dev, and Kubernetes.

---

## 2. Architecture & Deployment Matrix

```
                      ┌─────────────────────────────────────────────────────────────┐
                      │                 AegisVault Deployment Options               │
                      └──────────────────────────────┬──────────────────────────────┘
                                                     │
         ┌───────────────────────────┬───────────────┴───────────────┬───────────────────────────┐
         ▼                           ▼                               ▼                           ▼
┌───────────────────┐       ┌─────────────────┐             ┌─────────────────┐         ┌─────────────────┐
│  1. Docker Compose│       │ 2. Native Linux │             │ 3. Native Local │         │ 4. Kubernetes   │
│  (Production)     │       │    Systemd (VM) │             │    Dev (Script) │         │    (Cloud / K8s)│
├───────────────────┤       ├─────────────────┤             ├─────────────────┤         ├─────────────────┤
│ • Multi-container │       │ • systemd units │             │ • aegisvault-ctl│         │ • Helm chart    │
│ • Docker compose  │       │ • Zero Docker   │             │   dev           │         │ • DaemonSet /   │
│ • Air-gapped img  │       │ • Nginx proxy   │             │ • Hot reloading │           Deployment      │
│ • Isolated net    │       │ • Native perf   │             │ • No container  │         │ • Auto-scaling  │
└───────────────────┘       └─────────────────┘             └─────────────────┘         └─────────────────┘
```

---

## 3. User Review Required

- **Native Systemd vs. Background Process Runner:**
  - In production environments on Linux VMs/servers, `systemd` provides automatic restart on failure, journald logging, and boot-time startup (`systemctl enable aegisvault.target`).
  - For developer machines without `sudo` access or systemd, `aegisvault-ctl` also includes a lightweight process supervisor mode that manages background PID files in `run/` without requiring root privileges.
- **Database & Redis Provisioning:**
  The installer script will automate `PostgreSQL` and `Redis` user/database creation when run with `sudo`, or provide copy-paste SQL commands if connecting to an existing external database.

---

## 4. Proposed Changes

### Component 1: Native Installation & Process Controller Scripts
- **[NEW] `scripts/install_linux.sh`**: Automatic OS package manager detection (`apt`, `dnf`, `pacman`), Postgres/Redis configuration, Python venv, Node dependencies, and Go binary builds.
- **[NEW] `scripts/aegisvault_ctl.sh`**: Single-command controller supporting `start`, `stop`, `status`, `restart`, `logs`, `dev`, and `systemd install`.

### Component 2: Systemd Unit Definitions
- **[NEW] `deploy/systemd/aegisvault.target`**: Master systemd target.
- **[NEW] `deploy/systemd/aegisvault-api.service`**: FastAPI Uvicorn service unit.
- **[NEW] `deploy/systemd/aegisvault-worker.service`**: Celery worker service unit.
- **[NEW] `deploy/systemd/aegisvault-beat.service`**: Celery Beat scheduler service unit.
- **[NEW] `deploy/systemd/aegisvault-web.service`**: Next.js Web Console service unit.

### Component 3: Nginx Reverse Proxy Template
- **[NEW] `deploy/nginx/aegisvault.conf`**: Production Nginx configuration for reverse-proxying API (`/api/v1`), UI (`/`), and WebSockets with TLS and hardened security headers.

### Component 4: Documentation & Guide Synchronization
- **[NEW] `docs/DEPLOYMENT_OPTIONS.md`**: Authoritative comparison and step-by-step instructions for all 4 deployment modes.
- **[MODIFY] `docs/LOCAL_LINUX_INSTALL.md`**: Updated with automated installer and `aegisvault-ctl` commands.
- **[MODIFY] `README.md`**: Add deployment options matrix.

---

## 5. Verification Plan
- Bash syntax validation (`bash -n`) on all installer and controller scripts.
- Validate systemd unit files and directory structure.
- Execute full test suite (`150/150 tests`).

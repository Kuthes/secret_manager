# AegisVault — Deployment Options & Infrastructure Guide

AegisVault provides multiple deployment strategies to fit diverse infrastructure requirements — from minimalist bare-metal Linux servers and secure air-gapped enclaves to automated Docker containers and multi-node Kubernetes clusters.

---

## Deployment Options Matrix

| Feature / Model | **1. Native Linux Systemd** (Bare-Metal / VM) | **2. Native Local Dev** (No Docker) | **3. Docker Compose** (Single-Node Container) | **4. Kubernetes** (Multi-Node Cloud) |
|---|---|---|---|---|
| **Target Environment** | Production VMs, Bare-Metal, Air-Gapped | Local Dev Workstations, CI Runners | Small/Medium Prod, Staging, Edge | Enterprise Cloud, EKS, GKE, AKS |
| **Docker / Container Dependency** | **None (Zero Docker)** | **None (Zero Docker)** | Docker Engine & Compose | Container Runtime & K8s |
| **Process Supervision** | `systemd` (`aegisvault.target`) | `aegisvault-ctl` (PID supervisor) | Docker Daemon / Restart Policies | K8s Pod Controllers & Deployments |
| **Reverse Proxy** | Nginx (`deploy/nginx/aegisvault.conf`) | Direct port binding (8000 / 3000) | Built-in / Traefik / Nginx | Ingress Controller / ALB / Ingress-Nginx |
| **Database & Cache** | Native PostgreSQL 16 & Redis 7 | Local PostgreSQL 16 & Redis 7 | Containerized Postgres & Redis | Cloud Managed (RDS/Cloud SQL) or StatefulSet |
| **Resource Overhead** | **Lowest (Zero Container virtualization)** | **Minimal** | Low | Moderate |
| **Startup Time** | **< 1 second** | **< 2 seconds** | ~5-10 seconds | ~15-30 seconds |

---

## Option 1: Native Linux Bare-Metal Installation (Zero Docker, Zero K8s)

Best for: High-performance bare-metal servers, secure on-premise VMs, air-gapped data centers, and environments where Docker daemon privileges are restricted.

### 1.1 Automated One-Command Installation

Run the automated installer on Ubuntu, Debian, Fedora, RHEL, Rocky, or Arch:

```bash
# Clone the repository
git clone git@github.com:Kuthes/secret_manager.git aegisvault
cd aegisvault

# Run the automated native installer
sudo ./scripts/install_linux.sh
```

### 1.2 Install & Enable Systemd Service Units

```bash
# Install systemd unit files to /etc/systemd/system/
sudo ./scripts/aegisvault_ctl.sh systemd install

# Start all AegisVault services
sudo systemctl start aegisvault.target

# Enable automatic start on boot
sudo systemctl enable aegisvault.target
```

### 1.3 Service Control Commands

```bash
# Check status across all components
sudo systemctl status aegisvault.target

# Restart all services
sudo systemctl restart aegisvault.target

# View live API logs
journalctl -u aegisvault-api -f

# View live Celery Worker logs
journalctl -u aegisvault-worker -f
```

### 1.4 Production Nginx Reverse Proxy Setup

```bash
# 1. Install Nginx
sudo apt install -y nginx  # or: sudo dnf install -y nginx

# 2. Copy AegisVault site configuration
sudo cp deploy/nginx/aegisvault.conf /etc/nginx/sites-available/aegisvault.conf
sudo ln -s /etc/nginx/sites-available/aegisvault.conf /etc/nginx/sites-enabled/

# 3. Test and reload Nginx
sudo nginx -t
sudo systemctl reload nginx

# 4. Optional: Provision Free SSL Certificate with Certbot
sudo certbot --nginx -d vault.yourcompany.com
```

---

## Option 2: Native Local Development (No Docker)

Best for: Fast local development iterations without running Docker containers.

```bash
# 1. Setup local dependencies and virtualenv
./scripts/install_linux.sh

# 2. Launch interactive development supervisor (Hot reloading API + Next.js)
./scripts/aegisvault_ctl.sh dev
```

Or run background services locally:

```bash
# Start background processes
./scripts/aegisvault_ctl.sh start

# Check process health and port listeners
./scripts/aegisvault_ctl.sh status

# Stream logs
./scripts/aegisvault_ctl.sh logs

# Stop all processes
./scripts/aegisvault_ctl.sh stop
```

---

## Option 3: Production Docker Compose

Best for: Turnkey containerized single-node deployments on cloud VMs (AWS EC2, GCP Compute Engine, DigitalOcean Droplets).

```bash
# 1. Clone repository & configure .env
cp .env.example .env

# 2. Launch containerized stack
docker compose -f docker-compose.production.yml up --build -d

# 3. Inspect running containers
docker compose -f docker-compose.production.yml ps

# 4. Follow container logs
docker compose -f docker-compose.production.yml logs -f
```

---

## Option 4: Kubernetes & Enterprise Cloud

Best for: Multi-node enterprise clusters with automated horizontal pod autoscaling.

```bash
# 1. Apply Kubernetes manifests
kubectl apply -f deploy/kubernetes/

# 2. Verify pods and services
kubectl get pods -n aegisvault
kubectl get svc -n aegisvault
```

---

## 🔒 Security Hardening for Native Linux Deployments

1. **Dedicated Service User:**
   Run AegisVault under a non-root service account (e.g. `aegisvault`):
   ```bash
   sudo useradd -r -s /bin/false -d /opt/aegisvault aegisvault
   ```
2. **File Permissions:**
   Ensure `.env` containing master keys is restricted:
   ```bash
   chmod 600 .env
   chown aegisvault:aegisvault .env
   ```
3. **Firewall (UFW):**
   Block external access to internal database/cache ports:
   ```bash
   sudo ufw default deny incoming
   sudo ufw allow ssh
   sudo ufw allow 80/tcp
   sudo ufw allow 443/tcp
   sudo ufw enable
   ```

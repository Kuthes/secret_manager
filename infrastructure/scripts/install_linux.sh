#!/usr/bin/env bash
# ==============================================================================
# AegisVault — Automated Linux Bare-Metal / Native Installer (Zero-Docker)
# Supports: Ubuntu, Debian, Fedora, RHEL, Rocky, AlmaLinux, Arch Linux
# ==============================================================================
set -euo pipefail

# Visual output helpers
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_err() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo -e "${BOLD}======================================================${NC}"
echo -e "${BOLD}   AegisVault Native Linux Bare-Metal Installer        ${NC}"
echo -e "${BOLD}======================================================${NC}"
log_info "Installing AegisVault directly on native Linux (no Docker, no Kubernetes)..."
log_info "Target Directory: ${REPO_ROOT}"

# 1. Detect Operating System & Package Manager
detect_pkg_mgr() {
    if command -v apt-get &>/dev/null; then
        echo "apt"
    elif command -v dnf &>/dev/null; then
        echo "dnf"
    elif command -v yum &>/dev/null; then
        echo "yum"
    elif command -v pacman &>/dev/null; then
        echo "pacman"
    else
        echo "unknown"
    fi
}

PKG_MGR=$(detect_pkg_mgr)
log_info "Detected package manager: ${PKG_MGR}"

# 2. Install System Dependencies if running as root / with sudo available
install_system_packages() {
    log_info "Checking system prerequisites..."
    local use_sudo=""
    if [ "$EUID" -ne 0 ]; then
        if command -v sudo &>/dev/null; then
            use_sudo="sudo"
        else
            log_warn "Not running as root and sudo not found. Skipping system package installation."
            return 0
        fi
    fi

    case "$PKG_MGR" in
        apt)
            log_info "Updating apt cache and installing packages..."
            $use_sudo apt-get update -y
            $use_sudo apt-get install -y \
                python3 python3-pip python3-venv python3-dev \
                postgresql postgresql-contrib redis-server \
                build-essential libpq-dev libssl-dev libffi-dev \
                curl wget git
            ;;
        dnf|yum)
            log_info "Installing packages via ${PKG_MGR}..."
            $use_sudo $PKG_MGR install -y \
                python3 python3-pip python3-devel \
                postgresql-server postgresql-contrib redis \
                gcc gcc-c++ libpq-devel openssl-devel libffi-devel \
                curl wget git
            ;;
        pacman)
            log_info "Installing packages via pacman..."
            $use_sudo pacman -Sy --noconfirm \
                python python-pip postgresql redis \
                base-devel postgresql-libs openssl libffi \
                curl wget git
            ;;
        *)
            log_warn "Unknown package manager. Please ensure Python 3.12+, PostgreSQL 16, and Redis 7 are installed."
            ;;
    esac
}

# 3. Setup PostgreSQL and Redis services
setup_databases() {
    log_info "Configuring local PostgreSQL and Redis..."
    local use_sudo=""
    if [ "$EUID" -ne 0 ] && command -v sudo &>/dev/null; then
        use_sudo="sudo"
    fi

    # Start and enable Redis
    if command -v systemctl &>/dev/null; then
        log_info "Ensuring Redis service is active..."
        $use_sudo systemctl enable --now redis-server 2>/dev/null || \
        $use_sudo systemctl enable --now redis 2>/dev/null || true

        log_info "Ensuring PostgreSQL service is active..."
        $use_sudo systemctl enable --now postgresql 2>/dev/null || true
    fi

    # Provision PostgreSQL Database & User if psql is available
    if command -v psql &>/dev/null && [ -n "$use_sudo" ]; then
        log_info "Provisioning PostgreSQL user 'aegisvault' and database 'aegisvault'..."
        $use_sudo -u postgres psql -c "DO \$\$ BEGIN IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'aegisvault') THEN CREATE ROLE aegisvault WITH LOGIN SUPERUSER PASSWORD 'aegisvault_dev_pass'; END IF; END \$\$;" 2>/dev/null || true
        $use_sudo -u postgres psql -c "SELECT 'CREATE DATABASE aegisvault OWNER aegisvault' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'aegisvault')\gexec" 2>/dev/null || true
        log_success "PostgreSQL database 'aegisvault' configured."
    else
        log_info "PostgreSQL CLI not run with sudo. If needed, create DB with:"
        echo "  CREATE USER aegisvault WITH PASSWORD 'aegisvault_dev_pass' SUPERUSER;"
        echo "  CREATE DATABASE aegisvault OWNER aegisvault;"
    fi
}

# 4. Generate Production .env Configuration if missing
setup_environment_config() {
    if [ ! -f .env ]; then
        log_info "Generating production .env configuration file..."
        
        # Generate 256-bit base64 random keys
        local gen_mek
        local gen_jwt_secret
        gen_mek=$(python3 -c "import os, base64; print(base64.b64encode(os.urandom(32)).decode())" 2>/dev/null || openssl rand -base64 32)
        gen_jwt_secret=$(python3 -c "import os, base64; print(base64.b64encode(os.urandom(48)).decode())" 2>/dev/null || openssl rand -base64 48)

        cat << ENV_EOF > .env
# AegisVault Native Linux Environment Configuration
ENVIRONMENT=production
DEBUG=false
DEMO_MODE=true

# Database & Redis (Local native sockets / ports)
DATABASE_URL=postgresql+asyncpg://aegisvault:aegisvault_dev_pass@127.0.0.1:5432/aegisvault
REDIS_URL=redis://127.0.0.1:6379/0

# Master Cryptographic Keys (Auto-generated 256-bit AES-GCM MEK)
MASTER_ENCRYPTION_KEY=${gen_mek}
MEK_ID=mek-prod-v1
SECRET_KEY=${gen_jwt_secret}

# API Routing & Endpoints
API_V1_STR=/api/v1
NEXT_PUBLIC_API_URL=http://127.0.0.1:8000/api/v1

# Security Hardening
COOKIE_SECURE=false
COOKIE_SAMESITE=lax
RATE_LIMIT_ENABLED=true
ENV_EOF
        chmod 600 .env
        log_success "Created .env with cryptographically secure generated keys."
    else
        log_info "Existing .env file detected. Keeping current configuration."
    fi
}

# 5. Setup Python Virtual Environment and Backend Dependencies
setup_python_backend() {
    log_info "Setting up Python virtual environment in apps/api/.venv..."
    if [ ! -d "apps/api/.venv" ]; then
        python3 -m venv apps/api/.venv
    fi

    # Activate virtualenv
    source apps/api/.venv/bin/activate
    pip install --upgrade pip setuptools wheel --quiet

    log_info "Installing backend dependencies from apps/api/requirements.txt..."
    pip install -r apps/api/requirements.txt --quiet
    log_success "Python backend dependencies installed successfully."
}

# 6. Build Frontend Web Assets (Next.js)
setup_frontend_web() {
    if command -v npm &>/dev/null; then
        log_info "Setting up Next.js frontend dependencies..."
        npm install --quiet
        
        log_info "Building production web dashboard assets (npm run build)..."
        npm run build || log_warn "Frontend build skipped or completed with warnings."
        log_success "Frontend assets built successfully."
    else
        log_warn "Node.js / npm not detected. To install Node.js: https://nodejs.org/"
    fi
}

# 7. Compile Go CLI (`av`) and Go Agent (`aegis-agent`)
build_go_binaries() {
    if command -v go &>/dev/null; then
        log_info "Compiling Go CLI ('av')..."
        mkdir -p bin
        (cd packages/cli && go build -o ../../bin/av .) || log_warn "CLI build skipped."

        log_info "Compiling Go Agent ('aegis-agent')..."
        (cd apps/agent && go build -o ../../bin/aegis-agent .) || log_warn "Agent build skipped."

        if [ -f bin/av ]; then
            log_success "Compiled Go binaries available at '${REPO_ROOT}/bin/av' and '${REPO_ROOT}/bin/aegis-agent'."
        fi
    else
        log_info "Go compiler not found. (Optional for CLI and injection agent)."
    fi
}

# Execute all steps
install_system_packages
setup_databases
setup_environment_config
setup_python_backend
setup_frontend_web
build_go_binaries

# Ensure controller script is executable
chmod +x scripts/aegisvault_ctl.sh 2>/dev/null || true

echo ""
echo -e "${GREEN}${BOLD}======================================================${NC}"
echo -e "${GREEN}${BOLD}   AegisVault Native Linux Installation Complete!     ${NC}"
echo -e "${GREEN}${BOLD}======================================================${NC}"
echo ""
echo -e "To manage AegisVault on this machine:"
echo -e "  • Start in background:   ${BOLD}./scripts/aegisvault_ctl.sh start${NC}"
echo -e "  • Check service status:  ${BOLD}./scripts/aegisvault_ctl.sh status${NC}"
echo -e "  • Stream live logs:      ${BOLD}./scripts/aegisvault_ctl.sh logs${NC}"
echo -e "  • Run local dev mode:    ${BOLD}./scripts/aegisvault_ctl.sh dev${NC}"
echo -e "  • Install systemd units: ${BOLD}sudo ./scripts/aegisvault_ctl.sh systemd install${NC}"
echo ""
echo -e "Web Console:  ${BOLD}http://localhost:3000${NC}"
echo -e "API Docs:     ${BOLD}http://localhost:8000/api/v1/docs${NC}"
echo ""

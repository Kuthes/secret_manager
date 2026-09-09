#!/usr/bin/env bash
# ==============================================================================
# AegisVault — Native Process & Service Controller (Zero-Docker)
# Commands: start | stop | restart | status | logs | dev | systemd
# ==============================================================================
set -eo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

RUN_DIR="${REPO_ROOT}/run"
LOG_DIR="${REPO_ROOT}/logs"
mkdir -p "$RUN_DIR" "$LOG_DIR"

PID_API="${RUN_DIR}/api.pid"
PID_WORKER="${RUN_DIR}/worker.pid"
PID_BEAT="${RUN_DIR}/beat.pid"
PID_WEB="${RUN_DIR}/web.pid"

LOG_API="${LOG_DIR}/api.log"
LOG_WORKER="${LOG_DIR}/worker.log"
LOG_BEAT="${LOG_DIR}/beat.log"
LOG_WEB="${LOG_DIR}/web.log"

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

# Activate Python virtualenv if available
activate_venv() {
    if [ -f "${REPO_ROOT}/apps/api/.venv/bin/activate" ]; then
        source "${REPO_ROOT}/apps/api/.venv/bin/activate"
    elif command -v uv &>/dev/null; then
        export VIRTUAL_ENV="${REPO_ROOT}/apps/api/.venv"
    fi
}

is_running() {
    local pid_file="$1"
    if [ -f "$pid_file" ]; then
        local pid
        pid=$(cat "$pid_file" 2>/dev/null || true)
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            return 0
        fi
    fi
    return 1
}

# 1. Start Services in Background
start_services() {
    echo -e "${BOLD}Starting AegisVault Native Services...${NC}"
    activate_venv

    # 1. API Server (Uvicorn)
    if is_running "$PID_API"; then
        log_info "API is already running (PID: $(cat "$PID_API"))."
    else
        log_info "Launching FastAPI backend on http://127.0.0.1:8000..."
        PYTHONPATH=.:sdk/python nohup python3 -m uvicorn apps.api.app.main:app --host 0.0.0.0 --port 8000 --workers 2 > "$LOG_API" 2>&1 &
        echo $! > "$PID_API"
        log_success "API started (PID: $(cat "$PID_API")). Logs: logs/api.log"
    fi

    # 2. Celery Asynchronous Worker
    if is_running "$PID_WORKER"; then
        log_info "Celery Worker is already running (PID: $(cat "$PID_WORKER"))."
    else
        log_info "Launching Celery asynchronous worker..."
        PYTHONPATH=. nohup celery -A apps.worker.celery_app worker --loglevel=info --concurrency=2 > "$LOG_WORKER" 2>&1 &
        echo $! > "$PID_WORKER"
        log_success "Celery Worker started (PID: $(cat "$PID_WORKER")). Logs: logs/worker.log"
    fi

    # 3. Celery Beat Scheduler
    if is_running "$PID_BEAT"; then
        log_info "Celery Beat is already running (PID: $(cat "$PID_BEAT"))."
    else
        log_info "Launching Celery Beat periodic scheduler..."
        PYTHONPATH=. nohup celery -A apps.worker.celery_app beat --loglevel=info > "$LOG_BEAT" 2>&1 &
        echo $! > "$PID_BEAT"
        log_success "Celery Beat started (PID: $(cat "$PID_BEAT")). Logs: logs/beat.log"
    fi

    # 4. Next.js Web Console
    if is_running "$PID_WEB"; then
        log_info "Web Console is already running (PID: $(cat "$PID_WEB"))."
    else
        if command -v npm &>/dev/null; then
            log_info "Launching Next.js Web Console on http://localhost:3000..."
            if [ -d ".next" ]; then
                nohup npm run start -- -p 3000 > "$LOG_WEB" 2>&1 &
            else
                nohup npm run dev -- -p 3000 > "$LOG_WEB" 2>&1 &
            fi
            echo $! > "$PID_WEB"
            log_success "Web Console started (PID: $(cat "$PID_WEB")). Logs: logs/web.log"
        else
            log_warn "npm not found. Web Console not started."
        fi
    fi

    echo ""
    echo -e "${GREEN}${BOLD}AegisVault is running!${NC}"
    echo -e "  • Web Console:  ${BOLD}http://localhost:3000${NC}"
    echo -e "  • API Endpoint: ${BOLD}http://localhost:8000/api/v1/docs${NC}"
    echo ""
}

# 2. Stop Services Gracefully
stop_services() {
    echo -e "${BOLD}Stopping AegisVault Services...${NC}"

    local components=(
        "Web Console:$PID_WEB"
        "Celery Beat:$PID_BEAT"
        "Celery Worker:$PID_WORKER"
        "FastAPI Backend:$PID_API"
    )

    for item in "${components[@]}"; do
        local name="${item%%:*}"
        local pid_file="${item##*:}"
        if [ -f "$pid_file" ]; then
            local pid
            pid=$(cat "$pid_file" 2>/dev/null || true)
            if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
                log_info "Stopping ${name} (PID: ${pid})..."
                kill -TERM "$pid" 2>/dev/null || true
                
                # Wait for graceful shutdown up to 5 seconds
                local count=0
                while kill -0 "$pid" 2>/dev/null && [ $count -lt 10 ]; do
                    sleep 0.5
                    count=$((count + 1))
                done

                # Force kill if still running
                if kill -0 "$pid" 2>/dev/null; then
                    log_warn "${name} did not stop gracefully. Sending SIGKILL..."
                    kill -9 "$pid" 2>/dev/null || true
                fi
                log_success "${name} stopped."
            fi
            rm -f "$pid_file"
        fi
    done
    log_success "All AegisVault services stopped."
}

# 3. Status Report
status_services() {
    echo -e "${BOLD}======================================================${NC}"
    echo -e "${BOLD}   AegisVault Native Services Status                  ${NC}"
    echo -e "${BOLD}======================================================${NC}"

    local all_healthy=true
    check_component() {
        local name="$1"
        local pid_file="$2"
        local port="$3"

        printf "%-20s " "$name:"
        if is_running "$pid_file"; then
            local pid
            pid=$(cat "$pid_file")
            local mem
            mem=$(ps -o rss= -p "$pid" 2>/dev/null | awk '{printf "%.1f MB", $1/1024}' || echo "N/A")
            echo -e "${GREEN}RUNNING${NC} (PID: ${pid}, Mem: ${mem})"
        else
            echo -e "${RED}STOPPED${NC}"
            all_healthy=false
        fi
    }

    check_component "FastAPI Backend" "$PID_API" 8000
    check_component "Celery Worker" "$PID_WORKER" ""
    check_component "Celery Beat" "$PID_BEAT" ""
    check_component "Web Console" "$PID_WEB" 3000

    echo ""
    # Quick API Health probe
    if is_running "$PID_API"; then
        local health_res
        health_res=$(curl -s http://127.0.0.1:8000/api/v1/health || true)
        if [[ "$health_res" =~ "healthy"|"status" ]]; then
            log_success "API Health Check: OK (${health_res})"
        else
            log_warn "API Port is responding but health endpoint returned: ${health_res:-timeout}"
        fi
    fi
}

# 4. Stream Logs
stream_logs() {
    local target="${1:-all}"
    case "$target" in
        api)
            tail -n 50 -f "$LOG_API"
            ;;
        worker)
            tail -n 50 -f "$LOG_WORKER"
            ;;
        beat)
            tail -n 50 -f "$LOG_BEAT"
            ;;
        web)
            tail -n 50 -f "$LOG_WEB"
            ;;
        all|*)
            log_info "Tailing all service logs (Ctrl+C to exit)..."
            tail -n 25 -f "$LOG_API" "$LOG_WORKER" "$LOG_BEAT" "$LOG_WEB"
            ;;
    esac
}

# 5. Interactive Dev Mode (Foreground multi-runner)
run_dev_mode() {
    echo -e "${BOLD}Starting AegisVault Interactive Development Mode...${NC}"
    activate_venv

    # Trap exit signal to cleanly stop background processes on Ctrl+C
    trap 'echo -e "\nStopping dev processes..."; kill $(jobs -p) 2>/dev/null || true; exit 0' SIGINT SIGTERM EXIT

    echo -e "Launching API on port 8000 with live reload..."
    PYTHONPATH=.:sdk/python python3 -m uvicorn apps.api.app.main:app --host 0.0.0.0 --port 8000 --reload &

    echo -e "Launching Celery Worker..."
    PYTHONPATH=. celery -A apps.worker.celery_app worker --loglevel=info &

    echo -e "Launching Next.js Dev Server on port 3000..."
    npm run dev -- -p 3000 &

    wait
}

# 6. Systemd Integration Helper
manage_systemd() {
    local action="${1:-status}"
    case "$action" in
        install)
            if [ "$EUID" -ne 0 ]; then
                log_err "Installing systemd units requires root/sudo privileges. Run: sudo ./scripts/aegisvault_ctl.sh systemd install"
                exit 1
            fi
            log_info "Installing systemd service units to /etc/systemd/system/..."
            
            # Substitute current user and path into service files
            local current_user="${SUDO_USER:-$USER}"
            for unit in deploy/systemd/*.service deploy/systemd/*.target; do
                local dest="/etc/systemd/system/$(basename "$unit")"
                sed -e "s|{{AEGIS_ROOT}}|${REPO_ROOT}|g" \
                    -e "s|{{AEGIS_USER}}|${current_user}|g" \
                    "$unit" > "$dest"
                chmod 644 "$dest"
                log_info "Installed $(basename "$dest")"
            done

            systemctl daemon-reload
            systemctl enable aegisvault.target
            log_success "Systemd units installed and enabled!"
            echo -e "You can now control AegisVault with:"
            echo -e "  ${BOLD}sudo systemctl start aegisvault.target${NC}"
            echo -e "  ${BOLD}sudo systemctl status aegisvault.target${NC}"
            echo -e "  ${BOLD}sudo systemctl restart aegisvault.target${NC}"
            ;;
        start|stop|restart|status)
            systemctl "$action" aegisvault.target
            ;;
        *)
            echo "Usage: $0 systemd [install|start|stop|restart|status]"
            ;;
    esac
}

# Main Command Dispatcher
COMMAND="${1:-status}"
shift || true

case "$COMMAND" in
    start)
        start_services
        ;;
    stop)
        stop_services
        ;;
    restart)
        stop_services
        sleep 1
        start_services
        ;;
    status)
        status_services
        ;;
    logs)
        stream_logs "${1:-all}"
        ;;
    dev)
        run_dev_mode
        ;;
    systemd)
        manage_systemd "${1:-status}"
        ;;
    help|--help|-h)
        echo "AegisVault Native Process Controller"
        echo ""
        echo "Usage: $0 <command> [options]"
        echo ""
        echo "Commands:"
        echo "  start               Start all services in background (API, Worker, Beat, Web)"
        echo "  stop                Stop all running services"
        echo "  restart             Restart all services"
        echo "  status              Display current service status and health checks"
        echo "  logs [component]    Stream logs (components: api, worker, beat, web, all)"
        echo "  dev                 Launch interactive development supervisor in foreground"
        echo "  systemd <action>    Manage systemd units (install, start, stop, status)"
        echo ""
        ;;
    *)
        log_err "Unknown command: '$COMMAND'"
        echo "Run '$0 help' for available commands."
        exit 1
        ;;
esac

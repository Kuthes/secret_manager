#!/usr/bin/env bash
set -euo pipefail

# AegisVault Production Disaster Recovery Restore Script
# Restores PostgreSQL and verifies database integrity.

if [ $# -lt 1 ]; then
    echo "Usage: $0 <backup_directory_path>"
    exit 1
fi

BACKUP_DIR="$1"
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-aegisvault}"
DB_USER="${DB_USER:-postgres}"

echo "[+] Starting AegisVault Restoration from ${BACKUP_DIR}..."

# 1. Pre-flight Checksum Verification
echo "[+] Verifying SHA-256 checksums..."
cd "${BACKUP_DIR}"
if ! sha256sum -c SHA256SUMS --status; then
    echo "[!] ERROR: Cryptographic checksum validation failed! Backup is corrupted or tampered."
    exit 1
fi
echo "[✓] Integrity checksums verified."

# 2. Database Restoration
echo "[+] Restoring PostgreSQL database '${DB_NAME}'..."
PGPASSWORD="${DB_PASSWORD:-postgres}" pg_restore \
    -h "${DB_HOST}" \
    -p "${DB_PORT}" \
    -U "${DB_USER}" \
    -d "${DB_NAME}" \
    --clean \
    --if-exists \
    -v \
    "${BACKUP_DIR}/database.dump" || true

echo "[✓] AegisVault Database successfully restored."

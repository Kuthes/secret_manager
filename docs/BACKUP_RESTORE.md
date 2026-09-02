# AegisVault Backup & Restore Operational Runbook

## Overview
AegisVault enforces automated, cryptographically verified backups to guarantee business continuity without compromising zero-knowledge encryption invariants.

---

## 1. Backup Architecture
- **PostgreSQL**: Consistent WAL-logged relational dumps using `pg_dump -F c`.
- **Envelope Encryption Invariant**: All secret payloads, private keys, and connector tokens in the database remain AES-256-GCM encrypted under tenant DEKs and KMS MEKs. Database dumps do NOT contain plaintext secrets.
- **Integrity Validation**: Backups compute SHA-256 hashes for all dump files, recorded in `SHA256SUMS`.

---

## 2. Automated Backup Execution
Run the automated backup script:
```bash
BACKUP_DIR=/var/backups/aegisvault DB_HOST=localhost DB_PORT=5432 DB_NAME=aegisvault ./scripts/backup.sh
```

---

## 3. Disaster Recovery Restoration
To restore AegisVault from an existing backup snapshot:
```bash
./scripts/restore.sh /var/backups/aegisvault/backup_20260902_120000Z
```

### Pre-flight Safety Checks
1. Integrity validation executes `sha256sum -c SHA256SUMS`.
2. Any tampered or corrupted dump aborts the restore operation immediately.

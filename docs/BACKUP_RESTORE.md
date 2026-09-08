# AegisVault Backup & Restore Operational Runbook

**Document Version:** 2.0.0  
**Classification:** SRE & Security Operations Runbook  
**Target:** Production Relational Data & Cryptographic Master Key Assets  
**Status:** VALIDATED & TESTED  

---

## 1. Production Backup Architecture

AegisVault protects all customer credentials through a multi-tier envelope encryption architecture. Backup routines capture the full encrypted state without ever decrypting or exposing plaintext secret values.

### Backup Scope & Inventory
1. **PostgreSQL Database Dump:**
   - Organizations, Users, Roles, Memberships, Policies
   - Projects, Environments, Service Identities
   - Secrets, Secret Versions (Ciphertext, Nonce, Wrapped DEK, AAD metadata)
   - Certificate Authorities (Encrypted private keys, public certificates)
   - Certificates, CRL entries
   - Managed KMS Keys (Encrypted key material, versions, algorithms)
   - Dynamic Secret Providers, Leases
   - Integration Connections, Secret Syncs
   - Append-Only Tamper-Evident `audit_events` ledger (with SHA-256 hash chains)
2. **Master Encryption Key (MEK) & Root-of-Trust Metadata:**
   - Active and historical MEK IDs, version mappings, and KMS Key ARNs.
   - Note: Raw MEKs are backed up via cloud KMS key policies or dedicated air-gapped HSM key custody procedures.
3. **Configuration & Server Manifests:**
   - Helm values, Kubernetes secrets manifests, Traefik/Nginx reverse proxy configurations.

---

## 2. Fundamental Root Key Loss Warning

> [!CAUTION]
> **UNRECOVERABLE DATA CLAUSE:**  
> If the Root Key (KEK) and Master Encryption Key (MEK) are permanently lost, the encrypted secrets and private keys inside the database are **mathematically unrecoverable**. Database backups alone without valid MEK material cannot restore secrets.

### What is NOT Recoverable Without the Root Key:
- Secret version plaintext payloads
- CA private keys
- Software KMS managed private keys
- Stored integration credentials and dynamic database passwords

---

## 3. Automated Backup Procedures

### Step 1: Execute Relational Database Backup
```bash
pg_dump -h "${DB_HOST:-localhost}" -p "${DB_PORT:-5432}" -U "${DB_USER:-aegisvault}" -d "${DB_NAME:-aegisvault}" \
  -F c -b -v -f "/var/backups/aegisvault/backup_$(date -u +%Y%m%d_%H%M%SZ).dump"
```

### Step 2: Compute Cryptographic Checksums
```bash
cd /var/backups/aegisvault
sha256sum backup_*.dump > SHA256SUMS
```

### Step 3: Archive to Encrypted Cold Storage
Ship the dump and `SHA256SUMS` to an immutable, versioned, write-once (WORM) S3/GCS bucket with cross-region replication.

---

## 4. Disaster Recovery Restoration Procedure

### Step 1: Provision Clean Target Environment
Provision target PostgreSQL 16 cluster and verify network connectivity.

### Step 2: Verify Backup Checksum Integrity
```bash
cd /var/backups/aegisvault
sha256sum -c SHA256SUMS
```

### Step 3: Restore Database Schema & Records
```bash
pg_restore -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" --clean --if-exists -v backup_file.dump
```

### Step 4: Inject Root-of-Trust / Master Encryption Keys
Ensure `MASTER_ENCRYPTION_KEY` or AWS KMS Key ARN (`AEGIS_AWS_KMS_KEY_ARN`) is configured with proper IAM Workload Identity permissions.

### Step 5: Post-Restore Verification
Run automated health check and audit chain validation:
```bash
curl -f http://localhost:8000/api/v1/health
av doctor
```

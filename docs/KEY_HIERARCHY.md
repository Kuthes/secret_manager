# AegisVault Cryptographic Key Hierarchy & Root-of-Trust Architecture

**Document Version:** 1.0.0  
**Target:** Cryptography & SRE Architecture  
**Status:** VERIFIED IMPLEMENTATION  

---

## 1. Cryptographic Hierarchy Overview

AegisVault enforces a 4-tier envelope encryption architecture designed for zero-plaintext key exposure, cryptographic agility, and non-destructive rewrapping.

```
┌────────────────────────────────────────────────────────────────────────┐
│ Tier 0: Root Key / Key Encrypting Key (KEK)                            │
│ - Hardware Security Module (PKCS#11) or Cloud KMS (AWS / GCP / Azure)  │
│ - Never exportable; protected by IAM / Workload Identity               │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ wraps / protects
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Tier 1: Master Encryption Key (MEK)                                    │
│ - 256-bit AES key versioned in memory / local key registry             │
│ - Lifecycle: ACTIVE ➔ DECRYPT_ONLY ➔ RETIRED                           │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ wraps (with AAD binding)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Tier 2: Data Encryption Key (DEK)                                      │
│ - Fresh, ephemeral 256-bit AES key generated per secret version        │
│ - Encrypted at rest using active MEK and authenticated context         │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ encrypts payload
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Tier 3: Secret Version Payload & Ciphertext                            │
│ - AES-256-GCM ciphertext + 12-byte random CSPRNG nonce + 128-bit tag   │
│ - Deterministic Authenticated Additional Data (AAD) binding context    │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Key Tier Specifications

### Tier 0: Root Key / Key Encrypting Key (KEK)
- **Purpose:** Protects the Master Encryption Key (MEK) across application restarts and cold storage.
- **Key Lifetime:** Indefinite / Managed by Cloud KMS annual rotation policies.
- **Storage Location:** AWS KMS (Customer Managed Key), Azure Key Vault HSM, Google Cloud KMS, or FIPS 140-2 Level 3 HSM.
- **Rotation Strategy:** Managed externally by Cloud KMS; version references stored alongside MEKs.
- **Compromise Impact:** Total compromise of all master keys if external IAM policies and KMS logs are breached.
- **Recovery Requirement:** Backup of KMS Key Policies, Disaster Recovery replicate keys across secondary regions.

### Tier 1: Master Encryption Key (MEK)
- **Purpose:** Wraps ephemeral Data Encryption Keys (DEKs) associated with secret versions, certificates, and dynamic secrets.
- **Key Lifetime:** 90 days active; indefinite retention in `DECRYPT_ONLY` state for historical decryption.
- **Storage Location:** Loaded in secure memory by `EnvelopeCryptoEngine` (and persisted encrypted in cold storage / environment config).
- **Rotation Strategy:** Zero-plaintext DEK rewrap. When MEK rotates (e.g. `mek-v1` ➔ `mek-v2`):
  1. `mek-v1` status is transitioned to `DECRYPT_ONLY`.
  2. `mek-v2` is activated for all new writes.
  3. Background worker rewraps historical DEKs without decrypting the underlying secret plaintext.
- **Compromise Impact:** Ability to decrypt all DEKs wrapped by that specific MEK version.
- **Recovery Requirement:** Secure offline cold storage backup of MEK material or KMS recovery key.

### Tier 2: Data Encryption Key (DEK)
- **Purpose:** Directly encrypts a single secret version payload.
- **Key Lifetime:** Ephemeral in memory during encryption/decryption; wrapped ciphertext stored permanently with the secret version.
- **Storage Location:** Stored encrypted in PostgreSQL `secret_versions.encrypted_data_key`.
- **Rotation Strategy:** Rotates whenever a new secret version is written or updated.
- **Compromise Impact:** Compromise of a single secret version only; no blast radius to other versions, keys, or tenants.
- **Recovery Requirement:** Recoverable from PostgreSQL backups provided the wrapping MEK is intact.

### Tier 3: Authenticated Additional Data (AAD) & Nonce Invariants
- **Purpose:** Cryptographically binds ciphertext to organizational context to defeat cross-tenant splicing, object swapping, and replay attacks.
- **AAD Composition:**
  ```json
  {
    "environment_id": "<uuid>",
    "org_id": "<uuid>",
    "project_id": "<uuid>",
    "secret_key": "<UPPERCASE_KEY_NAME>",
    "version": 1
  }
  ```
- **Nonce Invariant:** 12-byte (96-bit) cryptographically secure random buffer generated via `os.urandom(12)`. Nonce reuse across identical keys is mathematically impossible under CSPRNG entropy bounds.

---

## 3. Disaster Recovery & Root Key Loss Protocol

> [!CAUTION]
> **PERMANENT DATA LOSS WARNING:**  
> If the Root Encryption Key (KEK) and Master Encryption Keys (MEKs) are permanently lost and no backup exists, encrypted secret material stored in PostgreSQL is **mathematically impossible to recover**. Database backups alone without valid MEK material cannot restore secrets.

### Emergency Key Recovery Procedure
1. Verify database integrity and restore PostgreSQL snapshot.
2. Inject root KEK / MEK material into the target environment via secure KMS Workload Identity or environment injection (`MASTER_ENCRYPTION_KEY`).
3. Execute `av doctor` or `/api/v1/health` to verify KMS provider connectivity and MEK unwrap readiness.
4. Run tamper verification suite (`tests/security/test_crypto_adversarial.py`) to confirm zero corruption.

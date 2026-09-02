# AegisVault Technical Architecture

AegisVault is an enterprise secret management and security control plane platform designed for multi-tenant, cloud-native, and self-hosted environments.

---

## 1. System Architecture Diagram

```mermaid
graph TD
    Client["Client Browser / CLI / Agent"] --> |HTTPS / Bearer Auth| API["FastAPI Control Plane (apps/api)"]
    API --> |AES-256-GCM Envelope Encryption| CryptoEngine["Cryptographic Core (AESGCM + AAD)"]
    API --> |Async SQLAlchemy 2.0| Postgres["PostgreSQL 16 (Tenant-Scoped Data)"]
    API --> |Task Queue & Locks| Redis["Redis 7 (Cache / Broker / Locks)"]
    Redis --> Worker["Celery Worker (apps/worker)"]
    Redis --> Scheduler["Celery Beat Scheduler"]
    Worker --> |Rotations / Revocations| Targets["Databases / Cloud KMS / GitHub / Vercel"]
    Worker --> |Alerts / Notifications| Mailpit["Mailpit SMTP / Webhooks"]
```

---

## 2. Envelope Encryption Architecture

AegisVault implements real envelope encryption using Python's standard `cryptography.hazmat.primitives.ciphers.aead.AESGCM`:

```text
+------------------------------------------------------------------------+
|                          Master Key (MEK)                              |
|           (Stored in External KMS, HSM, or Mounted Secret)            |
+-----------------------------------+------------------------------------+
                                    | Wraps / Decrypts
                                    v
+------------------------------------------------------------------------+
|                 Encrypted Data Encryption Key (DEK)                    |
+-----------------------------------+------------------------------------+
                                    | Decrypts
                                    v
+------------------------------------------------------------------------+
|                      Ephemeral 32-Byte DEK                             |
+-----------------------------------+------------------------------------+
                                    | Encrypts / Decrypts with AAD
                                    v
+------------------------------------------------------------------------+
|                  Encrypted Secret Payload (Ciphertext)                 |
|       AAD: {"org_id": ..., "project_id": ..., "key": ..., "ver": ...}  |
+------------------------------------------------------------------------+
```

---

## 3. Core Capabilities

1. **Secret Versioning & Rollback**: Every secret write produces an immutable version record. Point-in-time rollbacks decrypt the historical target and append a new head version without overwriting history.
2. **Private PKI Engine**: Issues X.509 certificates from Root and Intermediate CAs, validates SAN DNS names, enforces profile constraints, and generates CRLs.
3. **Software KMS**: Provides AES-256-GCM, RSA-PSS, and Ed25519 cryptographic primitives for applications without direct access to raw private keys.
4. **Privileged Access Management (PAM)**: Provides time-bound access approvals with auto-expiration and justification requirements.
5. **Secret Scanner**: Analyzes code files for leaked credentials using regex patterns and Shannon entropy, generating safe redacted previews.
6. **Multi-Target Sync**: Connects to GitHub Actions, Vercel, AWS Secrets Manager, and Kubernetes Secrets.

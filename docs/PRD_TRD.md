# AegisVault — Product Requirements & Technical Reference Document (PRD & TRD)
### Enterprise Secret Management & AI Agent Security Layer | v1.0.0-RC1 Architecture & GA Roadmap

**Version:** 1.0.0-RC1 (Enterprise GA Architecture)  
**Date:** September 8, 2026  
**Status:** Verified & Released (`v1.0.0-rc1` Acceptance Passed)  
**Security Classification:** Highly Confidential / Enterprise Infrastructure  

---

## Document 1: Product Requirements Document (PRD)

### 1. Executive Summary & Problem Statement

AegisVault is an enterprise secret management platform (AWS Secrets Manager / Azure Key Vault class) engineered with a first-class security layer for AI agents and multi-tenant cloud infrastructure. It delivers hardware-grade envelope encryption, fine-grained access control, JIT privileged access management (PAM), dynamic credential generation, machine authentication gateways, and disaster recovery.

Compared to market incumbents like Infisical and HashiCorp Vault, AegisVault provides:
1. **Zero-Trust AI Agent Security**: Autonomous agents authenticate via scoped machine identities (Universal Auth, Kubernetes TokenReview, OIDC/JWT) and interact with secrets without exposing raw master credentials.
2. **Auditable Cryptographic Root-of-Trust**: 4-tier envelope encryption binding secrets with deterministic Authenticated Additional Data (AAD), zero-plaintext Master Encryption Key (MEK) rotation, and SHA-256 tamper-evident audit ledgers with SIEM streaming (JSONL/RFC 5424 Syslog).
3. **High-Density, Utilitarian UX**: Minimalist, console-first UI (AWS/GCP Secrets Manager aesthetic) prioritizing dense data tables, keyboard shortcuts (⌘K), and zero-clutter workflows.

---

### 2. Core Pillars & Capabilities (v1.0.0-RC1 Baseline)

| Pillar | Implemented & Verified Capabilities | Release Status |
| :--- | :--- | :--- |
| **Secrets Management** | AES-256-GCM envelope encryption, 12-byte CSPRNG nonces, deterministic AAD tenant binding, version history, rollback, direct key lookup, dual-tier reveal rate limiting. | **GA (v1.0.0-RC1)** |
| **Dynamic Secrets Engine** | On-demand ephemeral credential generation and leasing with TTLs for PostgreSQL, MySQL, MongoDB, and Redis. | **GA (v1.0.0-RC1)** |
| **Machine Identities** | Universal Auth (bcrypt secrets), Kubernetes ServiceAccount Auth (TokenReview API), and OIDC/JWT Auth (RFC 7519 with signature verification & `alg=none` rejection). | **GA (v1.0.0-RC1)** |
| **PKI & Certificate Engine** | X.509 Root and Intermediate CAs, leaf issuance (`ca=False`), SAN validation, and automated CRL distribution. | **GA (v1.0.0-RC1)** |
| **Privileged Access (PAM)** | Two-man approval workflows (self-approval forbidden), just-in-time lease elevation, and emergency revocation. | **GA (v1.0.0-RC1)** |
| **KMS Root-of-Trust** | Pluggable `KMSProvider` interface supporting `LocalKMSProvider` (multi-version registry) and `AWSKMSProvider` (IAM/Workload Identity). | **GA (v1.0.0-RC1)** |
| **Audit & SIEM Export** | Cryptographic SHA-256 hash chains with anti-tampering verification and streaming JSON, JSONL, and RFC 5424 Syslog export. | **GA (v1.0.0-RC1)** |
| **Developer Tooling** | Official Python SDK (`AegisVaultClient`), Go Enterprise CLI (`av`), Go Daemon Agent (`aegis-agent`), credential leak scanner with SARIF export. | **GA (v1.0.0-RC1)** |

---

### 3. User Personas & Workflows

| Persona | Primary Workflows | Key UI/API Needs |
| :--- | :--- | :--- |
| **Platform / DevOps Engineer** | Secret CRUD, CI/CD injection via `av run`, dynamic DB credentials, Kubernetes ServiceAccount authentication. | Dense secret tables, fast search (⌘K), CLI/SDK parity, single-command secret injection. |
| **Security Engineer** | Audit ledger validation, MEK rotation, PAM approval policies, CRL revocation, SSRF protection enforcement. | SIEM export streams, tamper-verification dashboard, two-man approval queues. |
| **AI / Agent Developer** | Granting scoped tools/secrets to autonomous agents without credential leakage. | Ephemeral machine tokens, single-query key resolution, secret reveal justification logging. |
| **Compliance / SRE Auditor** | Cold-start disaster recovery drills, SOC2 / ISO 27001 evidence gathering, container vulnerability scans. | Deterministic DR runbooks, SBOM artifacts, zero-plaintext backup integrity. |

---

### 4. UI/UX Requirements — Minimalist Console Design

**Design Philosophy**: *Enterprise Console, Not Marketing Dashboard.*
- **Flat Navigation**: Fixed left-rail (`Secrets`, `Dynamic Secrets`, `Certificates`, `Access (PAM)`, `KMS`, `Machine Auth`, `Audit Logs`, `Integrations`).
- **Dense Data Presentation**: Sortable, filterable tables optimized for scanning high volumes of secrets and versions.
- **Strict Color Semantics**: Grayscale UI base; semantic color reserved strictly for state (Green = Active/Valid, Amber = Expiring Soon, Red = Revoked/Tampered).
- **Inline Operations**: Fast contextual actions (Reveal, Copy, Rotate, Rollback, Revoke) via popovers and dropdowns without full-page navigation.
- **Keyboard-First Navigation**: Global command palette (⌘K) for immediate fuzzy jumping across organizations, projects, environments, and secrets.

---

### 5. Roadmap & Release Sequencing

| Phase | Milestone | Scope & Deliverables | Status |
| :--- | :--- | :--- | :--- |
| **Phase 1–6** | Core Architecture & Engine | Envelope crypto, basic PKI, KMS, Celery worker rotation, scanner, Next.js frontend. | **Completed** |
| **Phase 7** | Security Remediation Sprint | SEC-01 through SEC-08 (Tenant IDOR, RBAC matrix, PAM self-approval, SSRF blocker, Redlock concurrency, cookie hardening, rate limiting). | **Completed** |
| **Phase 8** | Production Resilience & DR | KMS abstraction (AWS KMS), MEK rotation, Machine Identity (K8s/OIDC), DR wipe/restore simulation, SIEM Syslog/JSONL streams, 100k nonce collision test. | **Completed** |
| **RC-01–44** | Release Candidate Validation | 44 Release Gates, Bandit/Gitleaks/pip-audit zero findings, CycloneDX SBOM, Go CLI/Agent 1.0.0-rc1, Production Compose. | **RC ACCEPTED** |
| **v1.1 (Next)** | Enterprise Agent Proxy | Dedicated `apps/agent-proxy` sidecar/gateway for transparent out-of-band secret injection without raw tool access. | Planned |
| **v1.2 (Next)** | Browser PAM Gateway | WebSockets-based SSH/psql/mysql terminal session broker with recorded, replayable cast streams and AI summarization. | Planned |

---

## Document 2: Technical Requirements Document (TRD)

### 1. System Architecture & Topology

```
+-----------------------------------------------------------------------------------+
|                                 AegisVault Gateway                                |
|                        (Traefik v3.0 / TLS 1.2+ / HSTS / CSP)                     |
+------------------------------------------+----------------------------------------+
                                           |
                    +----------------------+----------------------+
                    |                                             |
+-------------------v--------------------+      +-----------------v-----------------+
|          Frontend Web Console          |      |       Control Plane REST API      |
|  (Next.js 15, React 19, Tailwind v4)   |      |  (FastAPI, Pydantic v2, Python 3) |
+----------------------------------------+      +-----------------+-----------------+
                                                                  |
                  +-----------------------------------------------+-----------------------------------+
                  |                                               |                                   |
+-----------------v------------------+         +------------------v-----------------+      +----------v----------+
|       PostgreSQL 16 Engine         |         |          Redis 7.2 Cache           |      |    Celery Worker    |
| (AsyncPG, SQLAlchemy 2.0 Async,    |         | (Distributed Redlock, Rate Limit,  |      | (Rotation, Leases,  |
|  Strict Tenant Scoping, RLS-ready) |         |  Dynamic Credential Leases)        |      |  Scanner Tasks)     |
+------------------------------------+         +------------------------------------+      +---------------------+
```

---

### 2. Cryptographic Envelope Hierarchy & Invariants

```
+-------------------------------------------------------------------+
|               Cloud KMS / Hardware HSM Master KEK                 |
|             (AWS KMS arn:aws:kms:... / Local Master)              |
+---------------------------------+---------------------------------+
                                  |
                        wrap_key / unwrap_key
                                  |
+---------------------------------v---------------------------------+
|                 Master Encryption Key (MEK)                       |
|           (256-bit AES-GCM Key, Versioned Registry)               |
+---------------------------------+---------------------------------+
                                  |
                        wrap_key / unwrap_key
                                  |
+---------------------------------v---------------------------------+
|              Ephemeral Data Encryption Key (DEK)                  |
|          (Fresh 256-bit AES-GCM Key generated per version)        |
+---------------------------------+---------------------------------+
                                  |
                           AES-256-GCM Encrypt
                                  |
+---------------------------------v---------------------------------+
|                    Encrypted Secret Payload                       |
|     (Ciphertext + 12-byte CSPRNG Nonce + Deterministic AAD Tag)   |
+-------------------------------------------------------------------+
```

#### Cryptographic Invariants:
1. **DEK Isolation**: Every secret version is encrypted under a unique 32-byte ephemeral DEK with a fresh 12-byte CSPRNG nonce. Nonces are never reused.
2. **Deterministic AAD**: Anti-tampering and cross-tenant replay protection strictly binds:
   ```python
   aad = json.dumps({
       "environment_id": str(environment_id),
       "org_id": str(org_id),
       "project_id": str(project_id),
       "secret_key": str(secret_key),
       "version": int(version),
   }, sort_keys=True, separators=(",", ":")).encode("utf-8")
   ```
3. **Zero-Plaintext MEK Rotation**: Data Encryption Keys are rewrapped under new active MEKs without decrypting the underlying secret payload to plaintext.

---

### 3. Core Database Models & Entity Schema

| Model Class | Table Name | Key Attributes & Relationships |
| :--- | :--- | :--- |
| `Organization` | `organizations` | `id (UUID)`, `name`, `slug`, `memberships`, `projects`, `roles`, `service_identities` |
| `User` | `users` | `id (UUID)`, `email`, `hashed_password` (Argon2id), `mfa_enabled`, `is_active` |
| `Project` | `projects` | `organization_id`, `name`, `slug`, `environments` |
| `Environment` | `environments` | `project_id`, `name`, `slug` (`development`, `staging`, `production`) |
| `Secret` | `secrets` | `project_id`, `environment_id`, `key`, `current_version_num`, `versions`, `rotation` |
| `SecretVersion` | `secret_versions` | `secret_id`, `version`, `encrypted_value`, `nonce`, `encrypted_data_key`, `dek_nonce`, `mek_id`, `mek_version` |
| `DynamicSecretProvider` | `dynamic_secret_providers` | `organization_id`, `engine_type` (`postgres`, `mysql`, `mongodb`, `redis`), `config_encrypted`, `leases` |
| `DynamicSecretLease` | `dynamic_secret_leases` | `provider_id`, `username`, `lease_id`, `expires_at`, `revoked_at` |
| `ServiceIdentity` | `service_identities` | `organization_id`, `auth_method` (`universal`, `kubernetes`, `jwt_oidc`), `credentials_hash`, `allowed_subnets` |
| `CertificateAuthority` | `pki_authorities` | `organization_id`, `common_name`, `encrypted_private_key`, `certificate_pem`, `is_root`, `is_active` |
| `Certificate` | `pki_certificates` | `ca_id`, `serial_number`, `common_name`, `san_list`, `not_after`, `is_revoked`, `revocation_reason` |
| `AuditEvent` | `audit_events` | `organization_id`, `actor_id`, `action`, `resource_type`, `resource_id`, `ip_address`, `prev_event_hash`, `event_hash` |
| `AccessResource` | `pam_resources` | `organization_id`, `name`, `resource_type`, `target_host`, `access_requests` |
| `AccessRequest` | `pam_requests` | `resource_id`, `requester_id`, `status` (`pending`, `approved`, `rejected`, `revoked`), `approver_id`, `expires_at` |

---

### 4. Machine Identity Authentication Engine

AegisVault implements three production-grade machine authentication gateways under `/api/v1/auth/machine`:

1. **Universal Auth (`/machine/login`)**:
   - Client ID + Client Secret validated via Argon2id hash.
   - Enforces IP CIDR allowlists and returns short-lived scoped JWT access tokens.
2. **Kubernetes Auth (`/machine/k8s`)**:
   - Validates projected ServiceAccount JWT tokens using the Kubernetes `TokenReview` API (`client.authentication.k8s.io`).
   - Binds namespace, service account name, and cluster identity to project/environment roles.
3. **OIDC / JWT Machine Auth (`/machine/jwt`)**:
   - RFC 7519 JSON Web Token authentication with asymmetric signature validation (RS256/ES256).
   - Validates `iss` (Issuer), `aud` (Audience), expiration (`exp`), and explicitly rejects `alg=none` tokens.

---

### 5. Dynamic Secrets Engine Expansion

Located in `apps/api/app/core/dynamic_engines.py`, supporting four enterprise data backends:

- **PostgreSQL Engine**: Issues ephemeral roles via `CREATE ROLE ... WITH LOGIN PASSWORD ... VALID UNTIL ...; GRANT ...`.
- **MySQL Engine**: Issues ephemeral users via `CREATE USER ... IDENTIFIED BY ...; GRANT ...`.
- **MongoDB Engine**: Issues scoped database users via `createUser` command with customizable roles.
- **Redis Engine**: Issues ephemeral ACL users via `ACL SETUSER ... on >password ~keys +commands`.
- **Automated Lease Revocation**: Celery workers reconcile expired leases and issue `DROP ROLE` / `ACL DELUSER` commands.

---

### 6. Disaster Recovery & Backup Architecture

- **Cold-Start Restoration Process**:
  1. Restore PostgreSQL physical/logical dump (`pg_restore`).
  2. Inject root Master Encryption Key (MEK) from secure KMS / HSM.
  3. Start API control plane (`DEMO_MODE=false`, `COOKIE_SECURE=true`).
  4. Perform immediate cryptographic audit chain verification (`av audit verify`).
- **Cryptographic Guarantees**:
  - Database snapshots contain zero plaintext secret material.
  - Active and historical secret versions decrypt successfully post-restore.
  - Audit SHA-256 hash chains remain mathematically contiguous.

---

### 7. Security Hardening & Compliance Matrix

| Control Category | Implementation Details | Verified Status |
| :--- | :--- | :--- |
| **SSRF Prevention** | Universal DNS & IP blocker rejecting loopback (`127.0.0.1`), RFC 1918 subnets, cloud metadata (`169.254.169.254`), and IPv4-mapped IPv6. | **PASS** |
| **RBAC Authorization** | Granular action-level permissions (`secret:read`, `secret:reveal`, `secret:create`, `pki:issue`, `pam:approve`, `kms:decrypt`). | **PASS** |
| **PAM Guardrails** | Two-man rule enforced; self-approvals strictly rejected with `403 Forbidden`. | **PASS** |
| **Rate Limiting** | Dual-tier per-user (30 req/min) and per-org (100 req/min) rate limits on secret reveals backed by Redis. | **PASS** |
| **Network Isolation** | Production Compose isolates database and cache to `aegis-internal` network without host port exposure. | **PASS** |
| **Transport Security** | TLS 1.2/1.3 mandatory; HSTS, CSP, X-Frame-Options: DENY, Referrer-Policy, and Permissions-Policy headers enforced. | **PASS** |
| **Software Supply Chain** | CycloneDX 1.5 SBOM generated; Bandit, Semgrep, pip-audit, and Gitleaks verified with 0 vulnerabilities. | **PASS** |

# AegisVault Enterprise Security & Secrets Platform — Master Architecture Plan

## 1. Repository Assessment

- **Current State**: The repository contains an interactive React 19 / Next.js frontend built on Vite/Vinext with Tailwind CSS v4, Lucide icons, and Radix UI components. The UI currently utilizes in-memory seed state (`seedSecrets`, mock navigations).
- **Target State**: A self-hosted, production-capable, multi-tenant secrets and security management platform (AWS Secrets Manager / HashiCorp Vault / Infisical / Smallstep class) featuring:
  - Multi-tenant, multi-project, multi-environment architecture with tenant-isolated database storage.
  - Envelope encryption with AES-256-GCM and rotating Master Key Encryption Keys (MEKs).
  - Production FastAPI backend (Python 3.12/3.14) with SQLAlchemy 2.0 async, Alembic migrations, PostgreSQL 16 with RLS, and Redis 7.
  - Celery background workers and Celery Beat scheduler for automated rotation and dynamic credential revocation.
  - Private PKI / Certificate Authority management with X.509 issuance, CRL distribution, and renewal automation.
  - Software KMS supporting AES-256-GCM, RSA-PSS, and Ed25519 cryptographic operations.
  - Privileged Access Management (PAM) with time-bound approval workflows and auto-expiration.
  - Multi-target Secret Sync framework (GitHub Actions, Vercel, AWS Secrets Manager, Kubernetes Secrets).
  - Go Secret Injection Agent (`aegis-agent`) and CLI (`av`).
  - Gitleaks-based secret scanning framework with baseline support and SARIF output.
  - Complete Docker Compose orchestration with PostgreSQL, Redis, Mailpit, API, Web, Worker, and Scheduler.

---

## 2. Monorepo Architecture & Directory Structure

```text
aegisvault/
├── apps/
│   ├── web/                    # Next.js / React 19 web control plane (preserved frontend)
│   ├── api/                    # FastAPI backend service (Python 3.12, Pydantic v2, SQLAlchemy async)
│   ├── worker/                 # Celery asynchronous worker service
│   └── agent/                  # Go secret injection agent (aegis-agent)
├── packages/
│   ├── cli/                    # Go cross-platform CLI tool (av)
│   ├── sdk-typescript/         # TypeScript API client & SDK
│   ├── sdk-python/             # Python API client & SDK
│   ├── shared-types/           # Shared JSON schemas & types
│   └── detection-rules/        # Secret scanning regex & entropy rules
├── integrations/
│   ├── github/                 # GitHub Actions secret sync connector
│   ├── vercel/                 # Vercel env-var sync connector
│   ├── aws/                    # AWS Secrets Manager & Parameter Store connector
│   ├── terraform/              # Terraform provider integration
│   └── kubernetes/             # Kubernetes Secret operator & sync connector
├── deploy/
│   ├── docker/                 # Production & local Dockerfiles & entrypoints
│   ├── kubernetes/             # Kubernetes manifests
│   └── helm/                   # Helm charts
├── docs/
│   ├── ARCHITECTURE.md
│   ├── THREAT_MODEL.md
│   ├── IMPLEMENTATION_STATUS.md
│   └── guides/
├── scripts/                    # Init, migration, and setup scripts
├── tests/                      # Unit, integration, e2e, and security test suites
├── docker-compose.yml          # Local orchestration
├── docker-compose.production.yml
├── Makefile                    # Standard operations makefile
├── .env.example
├── SECURITY.md
├── CONTRIBUTING.md
├── LICENSE
└── README.md
```

---

## 3. Core Database Model Summary (PostgreSQL 16)

All tables use UUID v4 primary keys, timestamps (`created_at`, `updated_at`), soft-deletion (`deleted_at`), and organization/project scoping:

1. **Identity & Access Management**:
   - `users`: `id`, `email`, `hashed_password` (Argon2id), `full_name`, `is_active`, `is_verified`, `mfa_enabled`, `mfa_secret`, `mfa_recovery_codes` (encrypted).
   - `organizations`: `id`, `name`, `slug`, `created_at`.
   - `organization_memberships`: `id`, `organization_id`, `user_id`, `role_id`.
   - `roles`: `id`, `name`, `slug`, `organization_id` (nullable for system roles), `description`.
   - `permissions`: `id`, `role_id`, `action` (`secret:create`, `secret:reveal`, `kms:encrypt`, etc.), `resource_scope`.
   - `projects`: `id`, `organization_id`, `name`, `slug`, `description`.
   - `project_memberships`: `id`, `project_id`, `user_id`, `role_id`.
   - `environments`: `id`, `project_id`, `name` (`development`, `staging`, `production`, custom), `slug`.
   - `service_identities`: `id`, `organization_id`, `name`, `auth_token_hash`, `scopes`, `expires_at`.
   - `api_keys`: `id`, `user_id`, `organization_id`, `name`, `key_prefix`, `key_hash`, `scopes`, `expires_at`.

2. **Secrets & Envelope Encryption**:
   - `secret_folders`: `id`, `project_id`, `environment_id`, `parent_id`, `name`, `path`.
   - `secrets`: `id`, `project_id`, `environment_id`, `folder_id`, `key`, `comment`, `current_version_id`.
   - `secret_versions`: `id`, `secret_id`, `version`, `encrypted_value`, `nonce`, `tag`, `encrypted_data_key`, `mek_id`, `mek_version`, `change_type` (`create`, `update`, `rollback`, `rotation`), `change_message`, `metadata_hash`, `actor_id`, `actor_type`, `created_at`.
   - `secret_rotations`: `id`, `secret_id`, `provider_type`, `interval_seconds`, `next_run_at`, `last_run_at`, `status`, `config_encrypted`.

3. **Dynamic Secrets & Leases**:
   - `dynamic_secret_providers`: `id`, `project_id`, `environment_id`, `provider_type` (`postgres`, `mysql`, `aws_sts`, `ssh`), `config_encrypted`, `max_ttl_seconds`, `default_ttl_seconds`.
   - `dynamic_credential_leases`: `id`, `provider_id`, `issued_identity`, `credential_encrypted`, `ttl_seconds`, `expires_at`, `revoked_at`, `status`.

4. **Delivery & Integrations**:
   - `integration_connections`: `id`, `organization_id`, `provider_type` (`github`, `vercel`, `aws`, `kubernetes`), `name`, `credentials_encrypted`, `status`, `last_health_check`.
   - `secret_syncs`: `id`, `project_id`, `environment_id`, `connection_id`, `target_path`, `sync_status`, `last_sync_at`.
   - `secret_sync_runs`: `id`, `sync_id`, `status`, `synced_keys_count`, `error_message_redacted`, `created_at`.

5. **PKI & Certificate Management**:
   - `certificate_authorities`: `id`, `organization_id`, `name`, `type` (`root`, `intermediate`), `cert_pem`, `encrypted_private_key`, `key_algorithm`, `subject_dn`, `valid_from`, `valid_to`, `crl_number`, `status`.
   - `certificate_profiles`: `id`, `organization_id`, `name`, `max_validity_days`, `key_usages`, `extended_key_usages`, `allowed_domains`.
   - `certificates`: `id`, `ca_id`, `profile_id`, `serial_number`, `common_name`, `san_dns_names`, `cert_pem`, `encrypted_private_key` (optional), `valid_from`, `valid_to`, `revocation_reason`, `revoked_at`.

6. **Key Management Service (KMS)**:
   - `managed_keys`: `id`, `organization_id`, `project_id`, `name`, `algorithm` (`AES-256-GCM`, `RSA-4096`, `Ed25519`), `encrypted_key_material`, `status`, `version`.
   - `encryption_operations`: `id`, `key_id`, `operation_type` (`encrypt`, `decrypt`, `sign`, `verify`), `actor_id`, `created_at`.

7. **Privileged Access & PAM**:
   - `access_resources`: `id`, `organization_id`, `project_id`, `resource_type`, `resource_identifier`, `approval_policy`.
   - `access_requests`: `id`, `resource_id`, `requester_id`, `justification`, `duration_seconds`, `status` (`pending`, `approved`, `rejected`, `expired`), `expires_at`.
   - `access_approvals`: `id`, `request_id`, `approver_id`, `decision`, `comment`, `created_at`.

8. **Audit & Notifications**:
   - `audit_events`: `id`, `organization_id`, `project_id`, `actor_id`, `actor_type`, `action`, `resource_type`, `resource_id`, `result`, `request_id`, `source_ip`, `user_agent`, `metadata_json`, `prev_event_hash`, `event_hash`, `created_at`.
   - `alert_rules`: `id`, `organization_id`, `event_type`, `channel_type` (`email`, `webhook`, `in_app`), `channel_config_encrypted`.
   - `notifications`: `id`, `user_id`, `organization_id`, `title`, `message`, `read_at`, `created_at`.
   - `scan_jobs`: `id`, `project_id`, `source_type`, `status`, `findings_count`, `created_at`.
   - `scan_findings`: `id`, `job_id`, `rule_id`, `file_path`, `line_number`, `secret_fingerprint`, `redacted_preview`, `status`, `resolution`.

---

## 4. Threat Model Summary (STRIDE & Defense-in-Depth)

| Threat | Mitigation |
|---|---|
| **Data Breach / Database Compromise** | Secret values are envelope-encrypted with AES-256-GCM using isolated DEKs wrapped by an external MEK; PostgreSQL stores only ciphertext, nonces, and authentication tags. |
| **Tampering / Ciphertext Modification** | Authenticated Additional Data (AAD) binds Organization ID, Project ID, Environment ID, Secret Key, and Version to AESGCM. Modification triggers tag mismatch and decryption failure. |
| **Credential Leakage in Logs** | Strict redaction middleware; custom log formatters sanitizing any `sk_`, `token`, `password`, `key` parameters; raw secrets never passed in URLs or query strings. |
| **Privilege Escalation & Insecure Direct Object Reference (IDOR)** | Every query enforces `organization_id` and project scope server-side with RBAC permissions checking (`secret:reveal`, `pki:revoke`, etc.). Secret listing APIs omit secret values. |
| **Replay & Secret Scraping** | Idempotency keys on mutations; rate limiting in Redis; ephemeral single-use session tokens and nonces. |
| **Server-Side Request Forgery (SSRF)** | Outbound webhooks and sync adapters validate destination IPs against private RFC1918 and loopback blocks (`127.0.0.1`, `10.0.0.0/8`, `169.254.169.254`). |

---

## 5. Phased Implementation Roadmap

- **Phase 1: Foundation & Monorepo Structure**
  - Restructure project into monorepo layout (`apps/web`, `apps/api`, `apps/worker`, `apps/agent`, `packages/cli`, `integrations/`).
  - Configure Docker Compose with PostgreSQL 16, Redis 7, Mailpit, FastAPI API, Next.js Web, Celery Worker.
  - Setup FastAPI app with Pydantic v2, async SQLAlchemy 2, Alembic migrations, and Argon2id authentication.
  - Seed demo data (Acme Cloud, Saurabh Kuthe, Payments API).
  - Connect web frontend API client to real FastAPI endpoints.

- **Phase 2: Secret Management & Envelope Encryption**
  - Implement crypto service using Python `cryptography` (AES-256-GCM envelope encryption).
  - Build Secret CRUD, versioning, immutable history, and point-in-time rollback endpoints.
  - Connect frontend Secrets table, reveal modal, add dialog, and rollback drawer to live API.

- **Phase 3: Worker Automation & Dynamic Secrets**
  - Implement Celery tasks for scheduled secret rotations and credential lease management.
  - Local providers for PostgreSQL/MySQL password rotation and temporary dynamic database users.
  - In-app alerts and email notifications via local Mailpit.

- **Phase 4: Sync Connectors, CLI & Agent**
  - Implement Integration connectors: GitHub Actions, Vercel, AWS Secrets Manager, and Kubernetes Secrets.
  - Build cross-platform Go CLI (`av`) with full command suite.
  - Build lightweight Go Secret Injection Agent (`aegis-agent`) with runtime environment injection.

- **Phase 5: PKI, KMS & Privileged Access Management**
  - Private PKI engine: Root & Intermediate CA generation, X.509 issuance, SAN validation, revocation, and CRL generation.
  - Managed KMS: AES-256-GCM, RSA-PSS, Ed25519 encrypt/decrypt/sign/verify.
  - Privileged Access Management: Time-bound requests, multi-approver workflow, auto-expiry.

- **Phase 6: Secret Scanner, CI/CD, Documentation & Acceptance Testing**
  - Gitleaks-compatible scanner engine with rule detection and SARIF report generation.
  - Comprehensive unit, integration, and security test suites.
  - Production Docker Compose, Makefile, and complete operational documentation.

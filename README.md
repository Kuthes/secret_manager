# AegisVault — Enterprise Security & Secrets Management Platform

AegisVault is a production-grade, self-hosted, open-source secret management and security control plane platform (AWS Secrets Manager / HashiCorp Vault / Infisical / Smallstep class).

---

## Architecture Overview

```text
aegisvault/
├── apps/
│   ├── web/                    # Next.js 15 & React 19 UI Dashboard
│   ├── api/                    # FastAPI Backend (Python 3.12, Async SQLAlchemy 2.0)
│   ├── worker/                 # Celery Asynchronous Workers
│   └── agent/                  # Go Secret Injection Agent (aegis-agent)
├── packages/
│   ├── cli/                    # Go CLI tool (av)
│   └── shared-types/           # Shared schemas and validation
├── integrations/
│   ├── github/                 # GitHub Actions secret sync connector
│   ├── vercel/                 # Vercel environment variables sync connector
│   ├── aws/                    # AWS Secrets Manager sync connector
│   └── kubernetes/             # Kubernetes Secret sync operator
├── deploy/
│   ├── docker/                 # Production Dockerfiles
│   └── kubernetes/             # Manifests & Helm charts
├── docs/                       # Architecture, Threat Model, Implementation Status
└── tests/                      # Unit, Integration, and Security Test Suites
```

---

## Key Features

1. **Envelope Encryption Core**:
   - AES-256-GCM authenticated payload encryption.
   - Distinct 32-byte ephemeral Data Encryption Keys (DEKs) per secret version.
   - Master Key Encryption Keys (MEKs) with versioning and re-wrapping support.
   - Authenticated Additional Data (AAD) cryptographically binding Organization ID, Project ID, Environment ID, Secret Key, and Version.
2. **Immutable Secret Versioning & Rollback**:
   - Every creation and update generates an immutable version record with actor telemetry.
   - Point-in-time rollback restores historical versions without overwriting audit history.
3. **Private PKI & Certificate Authority**:
   - Generates Root and Intermediate CAs.
   - Issues leaf X.509 certificates with SAN DNS names.
   - Manages certificate revocation and automated CRL generation.
4. **Software KMS**:
   - Symmetric AES-256-GCM encryption/decryption.
   - Asymmetric RSA-4096 and Ed25519 signing and verification.
   - Strict audit telemetry for every cryptographic operation.
5. **Privileged Access Management (PAM)**:
   - Time-bound access requests with required justifications and reviewer workflows.
   - Automatic lease expiration and early revocation.
6. **Automated Secret Rotation & Dynamic Credentials**:
   - Scheduled rotations via Celery Beat with Redis distributed locking.
   - Ephemeral database credentials with automatic lease cleanup.
7. **Secret Scanner**:
   - Real-time detection of leaked API keys, tokens, and private keys.
   - Generates SHA-256 fingerprints and redacted previews without storing plaintext leaks.
8. **Multi-Target Secret Delivery**:
   - Live connectors for GitHub Actions, Vercel, AWS Secrets Manager, and Kubernetes Secrets.
   - Lightweight Go runtime injection agent (`aegis-agent`).

---

## Quick Start (Local Development)

### 1. One-Command Setup with Docker Compose

```bash
# 1. Clone & enter repository
cd aegisvault-security-full-source

# 2. Copy environment template
cp .env.example .env

# 3. Start all services
docker compose up --build -d
```

### 2. Access the Platform

- **Web Dashboard**: [http://localhost:3000](http://localhost:3000) (or dev server at [http://localhost:5173](http://localhost:5173))
- **FastAPI Interactive Swagger Docs**: [http://localhost:8000/api/v1/docs](http://localhost:8000/api/v1/docs)
- **Mailpit Webmail (Alerts & Emails)**: [http://localhost:8025](http://localhost:8025)

---

## Demo Credentials (When `DEMO_MODE=true`)

| Parameter | Value |
|---|---|
| **Email** | `demo@aegisvault.local` |
| **Password** | `AegisDemo2026!` |
| **Organization** | `Acme Cloud` |
| **Project** | `Payments API` |
| **Environments** | `development`, `staging`, `production` |

---

## Running the Test Suite

```bash
# Run backend unit, envelope crypto, and API integration tests
PYTHONPATH=. ./apps/api/.venv/bin/pytest tests/test_crypto_and_api.py tests/test_api_integration.py

# Run frontend SSR and component test suite
npm test

# Run code style and accessibility linter
npm run lint
```

---

## CLI (`av`) Usage

```bash
# Authenticate
av login demo@aegisvault.local AegisDemo2026!

# List projects
av projects list

# Scan local directory for secrets
av scan .

# Run application with injected secrets
av run -- npm start
```

---

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.

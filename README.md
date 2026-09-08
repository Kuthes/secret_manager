# AegisVault — Enterprise Identity & Security Control Plane

[![Security Review](https://img.shields.io/badge/Security%20Audit-Verified-brightgreen.svg)](docs/SECURITY_AUDIT.md)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-blue.svg)](apps/api)
[![Next.js 15](https://img.shields.io/badge/Next.js-15.0-black.svg)](apps/web)
[![Go CLI & Agent](https://img.shields.io/badge/Go-1.22%2B-00ADD8.svg)](packages/cli)

AegisVault is an enterprise-grade, self-hostable identity security, secret management, and cryptographic control plane platform designed for cloud infrastructure and autonomous AI agent workloads.

---

## 🏛 Platform Pillars

| Pillar | Capabilities |
|---|---|
| **🔒 Secrets Management & Approval Workflows** | Envelope AES-256-GCM encryption, per-secret DEKs, deterministic AAD, PR-style change requests with dual-authorization (four-eyes principle), point-in-time versioning & rollback. |
| **🤖 AI Agent Proxy & Scoping Engine** | Ephemeral agent sessions, in-memory secret substitution (`{{ aegis:secret:<KEY> }}`), tool and domain allowlists, and anti-SSRF protection — agents never see plaintext credentials in prompt context. |
| **🔑 Machine Identity Gateways** | Universal Auth (client credentials), Kubernetes Service Account Auth (projected pod tokens), and OIDC/JWT machine identity exchange with auto-renewing access tokens. |
| **⚡ Dynamic Secrets Engine** | On-demand, short-lived ephemeral credentials with automatic TTL revocation across PostgreSQL, MySQL, Redis, AWS IAM, MongoDB, and HashiCorp Vault. |
| **📜 Private PKI & Certificate Authority** | Root and Intermediate CAs, leaf X.509 certificate issuance with SANs, automated CRL generation, and revocation controls. |
| **🛡 Software KMS** | Envelope DEK wrapping, AES-256-GCM symmetric encryption, and asymmetric RSA-4096 / Ed25519 signing and verification. |
| **⏱ Privileged Access Management (PAM)** | Time-bound access leases with mandatory justification, dual-authorization review, early revocation, and automated lease reclamation. |
| **🔍 Secret Scanner & Audit Hash Chains** | Real-time credential leak detection in codebases, SHA-256 fingerprinting, and tamper-evident cryptographic audit logs. |

---

## 🚀 Quick Start

### 1. Run Production Stack with Docker Compose

```bash
# Clone the repository
git clone git@github.com:Kuthes/secret_manager.git aegisvault
cd aegisvault

# Copy environment configuration
cp .env.example .env

# Launch all services (PostgreSQL 16, Redis 7, FastAPI API, Celery Workers, Next.js Web Console)
docker compose -f docker-compose.production.yml up --build -d
```

### 2. Access the Platform

- **Web Dashboard**: [http://localhost:3000](http://localhost:3000)
- **Interactive Swagger Docs**: [http://localhost:8000/api/v1/docs](http://localhost:8000/api/v1/docs)
- **Mailpit Email / Alert Console**: [http://localhost:8025](http://localhost:8025)

### 3. Demo Credentials (when `DEMO_MODE=true`)

| Parameter | Value |
|---|---|
| **Email** | `demo@aegisvault.local` |
| **Password** | `AegisDemo2026!` |
| **Organization** | `Acme Cloud` |
| **Project** | `Payments API` |

---

## 📦 Developer SDKs & CLI

### Python SDK (`sdk/python`)

```python
from sdk.python.aegisvault import AegisVaultClient

client = AegisVaultClient(
    base_url="http://localhost:8000",
    api_key="aegis_sec_...",
    project_id="PROJ_UUID",
    environment_id="ENV_UUID",
    cache_ttl_seconds=300,  # In-memory TTL caching with auto-fallback
)

# Fetch decrypted secret value
db_url = client.get_secret("DATABASE_URL", justification="Worker startup")
```

### Go CLI (`av`)

```bash
# Authenticate
av login demo@aegisvault.local AegisDemo2026!

# Scan local repository for leaked secrets
av scan .

# Run process with injected environment variables
av run -- npm start
```

---

## 🤖 AI Agent Proxy Example

Autonomous AI agents invoke external tools without ever holding raw secrets:

```bash
# Outbound tool call via AegisVault Agent Proxy
curl -X POST http://localhost:8000/api/v1/agents/proxy \
  -H "Authorization: Bearer aegis_ag_sess_..." \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "stripe.charge",
    "url": "https://api.stripe.com/v1/charges",
    "method": "POST",
    "headers": {
      "Authorization": "Bearer {{ aegis:secret:STRIPE_API_KEY }}",
      "Content-Type": "application/json"
    },
    "body": {"amount": 5000, "currency": "usd"}
  }'
```

*The proxy resolves `{{ aegis:secret:STRIPE_API_KEY }}` in-memory right before the TLS handshake and audits the request metadata.*

---

## 🧪 Testing & Verification

Run the full security and regression test suite (150+ tests):

```bash
# Run complete test suite
PYTHONPATH=.:sdk/python pytest tests/ -v

# Run AI Agent Proxy security suite
PYTHONPATH=.:sdk/python pytest tests/security/test_agent_proxy_security.py -v

# Run Secrets Approval Workflows suite
PYTHONPATH=.:sdk/python pytest tests/security/test_secrets_approval_workflows.py -v

# Run Machine Identity & Auth suite
PYTHONPATH=.:sdk/python pytest tests/security/test_machine_identity.py -v
```

---

## 📖 Documentation

- [📘 Comprehensive Usage Guide](docs/USAGE_GUIDE.md)
- [📋 Product & Technical Requirements Document (PRD & TRD)](docs/PRD_TRD.md)
- [🔐 Key Hierarchy & Cryptographic Architecture](docs/KEY_HIERARCHY.md)
- [🛡 Security Remediation Report](docs/SECURITY_REMEDIATION_REPORT.md)
- [💾 Backup & Disaster Recovery Runbook](docs/BACKUP_RESTORE.md)

---

## 📄 License

Apache License 2.0. See [LICENSE](LICENSE) for details.

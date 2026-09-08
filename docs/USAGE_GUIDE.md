# AegisVault — Comprehensive Usage & Integration Guide

AegisVault is an enterprise identity, secrets management, and cryptographic control plane platform designed for modern cloud infrastructure and autonomous AI workloads.

---

## Table of Contents

1. [Quick Start & Setup](#1-quick-start--setup)
2. [Authentication & Machine Identity](#2-authentication--machine-identity)
3. [Secrets Management & Approval Workflows](#3-secrets-management--approval-workflows)
4. [AI Agent Proxy & Scoping Engine](#4-ai-agent-proxy--scoping-engine)
5. [Python SDK Usage](#5-python-sdk-usage)
6. [Dynamic Secrets Engine](#6-dynamic-secrets-engine)
7. [Private PKI & Certificate Authority](#7-private-pki--certificate-authority)
8. [Software KMS & Cryptographic Operations](#8-software-kms--cryptographic-operations)
9. [Privileged Access Management (PAM)](#9-privileged-access-management-pam)
10. [Secret Scanner & CI/CD Integration](#10-secret-scanner--cicd-integration)
11. [Go CLI (`av`) Reference](#11-go-cli-av-reference)

---

## 1. Quick Start & Setup

### Running with Docker Compose

```bash
# 1. Clone repository
git clone git@github.com:Kuthes/secret_manager.git aegisvault
cd aegisvault

# 2. Configure environment
cp .env.example .env

# 3. Start production-grade stack (Postgres, Redis, API, Celery, Web)
docker compose -f docker-compose.production.yml up --build -d
```

### Access Endpoints

- **Web Console**: `http://localhost:3000` (Next.js 15 UI)
- **REST API & Swagger Docs**: `http://localhost:8000/api/v1/docs`
- **Mailpit Email UI**: `http://localhost:8025`

### Default Demo Credentials (when `DEMO_MODE=true`)

- **Email**: `demo@aegisvault.local`
- **Password**: `AegisDemo2026!`
- **Organization**: `Acme Cloud`

---

## 2. Authentication & Machine Identity

AegisVault supports user sessions, API keys, and machine authentication methods:

### 2.1 Universal Machine Auth (Client Credentials)

Issue a short-lived bearer token using `client_id` and `client_secret`:

```bash
curl -X POST http://localhost:8000/api/v1/auth/machine/universal \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "YOUR_CLIENT_ID",
    "client_secret": "YOUR_CLIENT_SECRET"
  }'
```

### 2.2 Kubernetes Service Account Auth

Exchange a projected Kubernetes pod service account JWT for an AegisVault token:

```bash
curl -X POST http://localhost:8000/api/v1/auth/machine/kubernetes \
  -H "Content-Type: application/json" \
  -d '{
    "role_name": "payments-api-role",
    "jwt": "'$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)'"
  }'
```

### 2.3 JWT / OIDC Machine Auth

```bash
curl -X POST http://localhost:8000/api/v1/auth/machine/oidc \
  -H "Content-Type: application/json" \
  -d '{
    "provider_id": "771e86a0-e221-4f40-8b1b-9a99786a9f5d",
    "jwt": "eyJhbGciOiJSUzI1NiIs..."
  }'
```

---

## 3. Secrets Management & Approval Workflows

### 3.1 Creating & Reading Secrets

All secrets are encrypted with per-secret ephemeral DEKs and AES-256-GCM envelope encryption.

```bash
# Store a secret
curl -X POST "http://localhost:8000/api/v1/secrets?project_id=PROJ_UUID&environment_id=ENV_UUID" \
  -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "key": "STRIPE_SECRET_KEY",
    "value": "sk_live_1122334455667788",
    "comment": "Stripe Live API Key"
  }'

# Reveal/Decrypt Secret (audited event)
curl -X GET "http://localhost:8000/api/v1/secrets/SECRET_UUID/reveal?justification=Incident+Response" \
  -H "Authorization: Bearer $AEGIS_TOKEN"

# Direct Key Lookup (fast single-query)
curl -X GET "http://localhost:8000/api/v1/secrets/value?project_id=PROJ_UUID&environment_id=ENV_UUID&key=STRIPE_SECRET_KEY&justification=Production+Deploy" \
  -H "Authorization: Bearer $AEGIS_TOKEN"
```

### 3.2 Dual-Authorization Change Requests (PR-Style Workflows)

Enforce four-eyes review on sensitive secret updates.

1. **Submit Change Request:**
```bash
curl -X POST http://localhost:8000/api/v1/change-requests \
  -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "project_id": "PROJ_UUID",
    "environment_id": "ENV_UUID",
    "change_type": "create",
    "title": "Add Database Master Password",
    "description": "Required for Q3 infrastructure upgrade",
    "proposed_key": "DATABASE_PASSWORD",
    "proposed_value": "SuperSecretPass123!"
  }'
```

2. **Review (Approve/Reject) by Authorized Reviewer (requester cannot self-approve):**
```bash
curl -X POST http://localhost:8000/api/v1/change-requests/CHANGE_REQ_UUID/review \
  -H "Authorization: Bearer $REVIEWER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "decision": "approved",
    "comment": "Verified change ticket INFRA-409"
  }'
```

3. **Apply Approved Change:**
```bash
curl -X POST http://localhost:8000/api/v1/change-requests/CHANGE_REQ_UUID/apply \
  -H "Authorization: Bearer $REVIEWER_TOKEN"
```

---

## 4. AI Agent Proxy & Scoping Engine

The AI Agent Proxy allows autonomous LLMs and agents to interact with external tools and APIs without ever exposing plaintext credentials in context windows.

### 4.1 Registering an Agent Identity with Scoping Policies

```bash
curl -X POST http://localhost:8000/api/v1/agents \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Billing Automation Agent",
    "slug": "billing-agent",
    "project_id": "PROJ_UUID",
    "environment_id": "ENV_UUID",
    "policy": {
      "allowed_tools": ["stripe.charge", "stripe.refund"],
      "allowed_domains": ["api.stripe.com"],
      "max_requests_per_minute": 60
    }
  }'
```

### 4.2 Generating an Ephemeral Session Token

```bash
curl -X POST http://localhost:8000/api/v1/agents/AGENT_UUID/sessions \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ttl_seconds": 3600}'
```

### 4.3 Executing Proxied Outbound Calls with In-Memory Secret Substitution

The agent calls `/api/v1/agents/proxy` using placeholder syntax `{{ aegis:secret:<KEY> }}`:

```bash
curl -X POST http://localhost:8000/api/v1/agents/proxy \
  -H "Authorization: Bearer aegis_ag_sess_..." \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "stripe.charge",
    "url": "https://api.stripe.com/v1/charges",
    "method": "POST",
    "headers": {
      "Authorization": "Bearer {{ aegis:secret:STRIPE_SECRET_KEY }}",
      "Content-Type": "application/json"
    },
    "body": {
      "amount": 2000,
      "currency": "usd"
    }
  }'
```

**Security Guarantees:**
- The agent never sees the decrypted key.
- Outbound requests to non-whitelisted domains or private IPs are blocked with 403/400 (SSRF defense).
- Full request telemetry is recorded in the immutable audit log.

---

## 5. Python SDK Usage

Install and use the official Python SDK with local in-memory TTL caching and auto-fallback.

```python
from sdk.python.aegisvault import AegisVaultClient

# Initialize client
client = AegisVaultClient(
    base_url="http://localhost:8000",
    api_key="aegis_sec_...",  # or token
    project_id="PROJ_UUID",
    environment_id="ENV_UUID",
    cache_ttl_seconds=300,  # 5-minute in-memory caching
)

# Fetch single secret by key name
db_url = client.get_secret("DATABASE_URL", justification="Worker startup")
print(f"Connected using: {db_url}")

# List all secrets in environment
secrets = client.list_secrets(path="/")
for s in secrets:
    print(f"Secret: {s['key']} (v{s['current_version']})")
```

---

## 6. Dynamic Secrets Engine

Generate on-demand, time-bound credentials for infrastructure engines:

Supported engines: `postgresql`, `mysql`, `redis`, `aws_iam`, `mongodb`, `vault`.

```bash
# Issue dynamic credential lease (e.g. 1-hour database user)
curl -X POST http://localhost:8000/api/v1/dynamic/providers/PROVIDER_UUID/leases \
  -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ttl_seconds": 3600}'

# Revoke lease early
curl -X POST http://localhost:8000/api/v1/dynamic/leases/LEASE_UUID/revoke \
  -H "Authorization: Bearer $AEGIS_TOKEN"
```

---

## 7. Private PKI & Certificate Authority

Manage internal Certificate Authorities and issue X.509 certificates.

```bash
# Create Root CA
curl -X POST http://localhost:8000/api/v1/pki/ca \
  -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Internal Root CA",
    "common_name": "AegisVault Root CA",
    "key_algorithm": "RSA-4096",
    "max_path_length": 2,
    "validity_days": 3650
  }'

# Issue Leaf Certificate
curl -X POST http://localhost:8000/api/v1/pki/certificates \
  -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ca_id": "CA_UUID",
    "common_name": "api.internal.company.com",
    "alt_names": ["api.internal.company.com", "api-fallback.internal.company.com"],
    "validity_days": 90
  }'
```

---

## 8. Software KMS & Cryptographic Operations

AegisVault provides software KMS for symmetric encryption and asymmetric signing:

```bash
# Sign payload with RSA-4096 or Ed25519
curl -X POST http://localhost:8000/api/v1/kms/keys/KEY_UUID/sign \
  -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"data": "PAYLOAD_BASE64"}'

# Verify signature
curl -X POST http://localhost:8000/api/v1/kms/keys/KEY_UUID/verify \
  -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "data": "PAYLOAD_BASE64",
    "signature": "SIGNATURE_BASE64"
  }'
```

---

## 9. Privileged Access Management (PAM)

Request temporary elevated access with mandatory business justification:

```bash
# 1. Request access
curl -X POST http://localhost:8000/api/v1/access/requests \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "resource_id": "RESOURCE_UUID",
    "justification": "Production DB migration INC-9081",
    "duration_seconds": 3600
  }'

# 2. Approve request (Admin)
curl -X POST http://localhost:8000/api/v1/access/requests/REQ_UUID/approve \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"comment": "Approved per change window"}'
```

---

## 10. Secret Scanner & CI/CD Integration

Scan codebases, repositories, and directories for leaked credentials before committing:

```bash
# Scan repository/path via API
curl -X POST http://localhost:8000/api/v1/scanner/scan \
  -H "Authorization: Bearer $AEGIS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "project_id": "PROJ_UUID",
    "target_path": "/workspace/source"
  }'
```

---

## 11. Go CLI (`av`) Reference

The standalone `av` CLI provides terminal operations:

```bash
# Login
av login demo@aegisvault.local AegisDemo2026!

# Scan current folder
av scan .

# Run application with injected environment variables
av run -- npm start

# List projects
av projects list
```

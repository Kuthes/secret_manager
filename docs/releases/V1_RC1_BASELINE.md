# AegisVault v1.0.0-RC1 Baseline

## Release Identity & Repository State

- **Target Release**: AegisVault v1.0.0-RC1
- **Target Type**: Release Candidate 1 (Strict Pre-Ship Validation)
- **Git Commit SHA**: `e18d676b7e0766be1b2c4535359e9844c803328d`
- **Git Branch**: `main`
- **Verification Timestamp**: 2026-09-08T13:50:00+05:30

---

## Component Version Manifest

| Component | Target Version | Engine / Runtime | Source Path |
| :--- | :--- | :--- | :--- |
| **Control Plane API** | `1.0.0-rc1` | Python 3.12+ / FastAPI / Pydantic v2 | `apps/api` |
| **Frontend Web Console** | `1.0.0-rc1` | Next.js 15 / React 19 / Tailwind v4 | `src/` |
| **Enterprise CLI (`av`)** | `1.0.0-rc1` | Go 1.26+ | `packages/cli/main.go` |
| **Daemon Agent (`aegis-agent`)** | `1.0.0-rc1` | Go 1.26+ | `apps/agent/main.go` |
| **Python SDK** | `1.0.0-rc1` | Python 3.10+ / httpx / pydantic | `sdk/python` |
| **Database Schema** | `1.0.0` (v1 base) | PostgreSQL 16 (AsyncPG / SQLAlchemy 2.0) | `apps/api/app/models` |
| **Cache & Distributed Lock** | Redis 7.2 | Redis Sentinel / Standalone | `apps/api/app/core` |

---

## Cryptographic & Security Baseline

1. **Envelope Encryption Hierarchy**:
   - Cloud KMS / Local HSM KEK ➔ Master Encryption Key (MEK) ➔ Ephemeral Data Encryption Key (DEK) ➔ AES-256-GCM Encrypted Payload (12-byte CSPRNG Nonce + Deterministic AAD).
2. **Deterministic Anti-Tamper AAD**:
   - `aad = f"tenant:{tenant_id}|secret:{secret_id}|v:{version_num}"`
3. **Machine Authentication Gateways**:
   - Universal Auth (Client ID + Client Secret with bcrypt hash).
   - Kubernetes Auth (Projected ServiceAccount Token validation against TokenReview API).
   - OIDC / JWT Auth (RFC 7519 signature & audience validation with mandatory `alg=none` rejection).
4. **Security Controls Verified in Phase 7/8**:
   - SEC-01: Tenant IDOR elimination.
   - SEC-02: RBAC authorization on all sensitive routes.
   - SEC-03: PAM self-approval prevention.
   - SEC-04: Strict tenant resolution (rejection of spoofed headers).
   - SEC-05: Distributed Redlock worker synchronization & idempotency.
   - SEC-06: Enterprise SSRF filtering on outbound webhooks and database connectors.
   - SEC-07: Production cookie hardening (`Secure`, `HttpOnly`, `SameSite=Lax`).
   - SEC-08: Secret reveal justification, dual-tier rate limiting, and audit logging.

---

## Baseline Test Execution Status

- Backend & Security Suites: 136 passing, 0 failing.
- Adversarial Cryptography: 8 passing, 0 failing (including 100k nonce collision safety).
- Machine Identity Suites: 3 passing, 0 failing.
- Disaster Recovery Simulation: 1 passing, 0 failing.
- Frontend Regression Suites: 5 passing, 0 failing.

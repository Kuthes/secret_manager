# AegisVault v1.0.0-RC1 Release Candidate Validation Plan

## Objectives
1. **Zero-Trust Validation**: Independently verify all security, cryptographic, tenant isolation, and disaster recovery controls without relying on self-reported claims.
2. **Deterministic Evidence**: Execute all test suites, black-box scenarios, fault injection drills, and static/vulnerability scans, archiving sanitized outputs into `artifacts/rc1/`.
3. **Release Readiness**: Formally evaluate the 44 release gates to determine RC classification (`BLOCKED`, `RC ACCEPTED WITH CONDITIONS`, or `RC ACCEPTED`), and prepare all release documentation and checklists without automatically publishing or creating final release tags.

---

## Phases & Execution Strategy

### RC-01: Freeze & Baseline
- Inspect git status, commit SHAs, active branch, and component versioning across backend, frontend, CLI, and agent.
- Create `docs/releases/V1_RC1_BASELINE.md`.

### RC-02: Acceptance Suite Baseline
- Create `artifacts/rc1/` directory hierarchy.
- Run `scripts/v1_acceptance.sh` and capture raw logs into `artifacts/rc1/acceptance.log`.

### RC-03 to RC-06: Clean Deployment, Network Exposure, TLS & Security Headers
- Inspect container configurations (`docker-compose.production.yml`, Dockerfiles).
- Verify port exposure rules (PostgreSQL 5432 and Redis 6379 strictly private, only reverse proxy on 443/80).
- Validate TLS termination, protocol rejection (TLS < 1.2 rejected), and HTTP security headers (HSTS, CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
- Record evidence in `artifacts/rc1/network-exposure.txt` and `artifacts/rc1/security-headers.txt`.

### RC-07 to RC-15: Black-Box Security, Auth, Multi-Tenancy, RBAC & SSRF
- Black-box authentication & session lifecycle verification (token invalidation, expired tokens, MFA, cookie security attributes).
- Multi-tenant black-box isolation testing (Organization RED vs Organization BLUE cross-tenant attempts returning 404).
- RBAC matrix validation (Owner, Admin, Developer, Viewer, Custom roles).
- API input security & malformed payload handling (deep nesting, invalid UUIDs, SQLi/NoSQL/path traversal strings).
- Error handling verification (no stack traces, credentials, or internal paths in HTTP responses).
- Secret leakage assessment (synthetic canary tokens across logs, stdout, error messages, and frontend assets).
- SSRF black-box validation on integration and webhook endpoints (loopback, RFC1918, link-local 169.254.169.254).
- Distributed rate limiting enforcement.

### RC-16 to RC-26: Cryptography, Key Rotation, Failures & Reliability
- Envelope encryption integrity & tamper-resistance (bit-flips, AAD tampering, nonce safety).
- Zero-downtime MEK rotation with multi-version historical secret decryption.
- Root-of-trust failure simulation (fail-closed behavior when KMS is unavailable).
- Machine identity validation (Universal Auth, K8s Auth, OIDC/JWT with signature & `alg=none` rejection).
- PKI CA hierarchy, leaf constraints (`ca=False`), and CRL certificate revocation persistence.
- KMS managed key operations and PAM two-man approval rules.
- Fault injection: Celery worker crash/recovery, Redis failure, and PostgreSQL failure.

### RC-27 to RC-29: Backup, Catastrophic DR & Audit Chain
- Full database backup generation.
- Catastrophic wipe and restore drill verifying active/historical secret decryption and CA/KMS continuity.
- Cryptographic audit ledger verification (`av audit verify`) and tamper detection.

### RC-30 to RC-36: Container, Dependency, SAST, Secret Scanning & SBOM
- Container image analysis and dependency vulnerability auditing.
- Static analysis via Bandit, Semgrep, and Gitleaks scanning.
- Software Bill of Materials (SBOM) generation in `artifacts/rc1/sbom/`.
- Production configuration auditing (`DEMO_MODE=true` rejection, image digest pinning, no default secrets).

### RC-37 to RC-39: CLI, Agent & Performance Sanity
- Go CLI (`av`) and Go Agent (`aegis-agent`) build and version verification (`1.0.0-rc1`).
- Latency and concurrency sanity benchmark stored in `artifacts/rc1/performance-summary.json`.

### RC-40 to RC-44: Release Notes, Operations Manual & Final Acceptance Report
- Consolidate all evidence in `artifacts/rc1/`.
- Produce `CHANGELOG.md`, `docs/releases/v1.0.0-rc1.md`, `docs/operations/SECURITY_OPERATIONS.md`.
- Produce final `docs/releases/V1_RC1_VALIDATION_REPORT.md` and `docs/releases/V1_RELEASE_CHECKLIST.md`.

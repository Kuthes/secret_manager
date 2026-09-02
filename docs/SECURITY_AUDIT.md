# AegisVault Internal Security Audit Report

**Assessment Target:** AegisVault Core Control Plane & Cryptographic Subsystems  
**Date:** September 2026  
**Status:** In Progress / Remediations Active  

---

## Findings Matrix

### SEC-01: Tenant IDOR on Direct Object References across Core APIs
- **Severity:** Critical
- **Affected Files:**
  - `apps/api/app/api/v1/secrets.py`
  - `apps/api/app/api/v1/pki.py`
  - `apps/api/app/api/v1/kms.py`
  - `apps/api/app/api/v1/projects.py`
  - `apps/api/app/api/v1/dynamic.py`
- **Risk:** An authenticated user in Organization A could view, decrypt/reveal, modify, rollback, or delete secrets, CAs, certificates, and KMS keys belonging to Organization B by supplying target UUIDs.
- **Fix:** Enforce explicit organizational ownership validation on all entity queries and lookups. Return 404 for unowned entities to maintain an anti-enumeration defense.
- **Test Created:** `tests/security/test_tenant_isolation.py`

---

### SEC-02: Missing Role-Based Access Control (RBAC) Enforcement
- **Severity:** Critical
- **Affected Files:** All API routes in `apps/api/app/api/v1/*.py`
- **Risk:** Any authenticated organization member (including low-privilege Viewer roles) could perform high-privilege operations such as `secret:create`, `secret:reveal`, `secret:delete`, `ca:create`, `kms:encrypt`, and `pam:approve`.
- **Fix:** Implement `require_permission(action: str)` FastAPI dependency with role-permission mapping and fallback checks. Reject unauthorized actions with 403 Forbidden.
- **Test Created:** `tests/security/test_rbac_matrix.py`

---

### SEC-03: PAM Self-Approval Vulnerability
- **Severity:** High
- **Affected Files:** `apps/api/app/services/pam_service.py`
- **Risk:** A privileged user requesting elevation can approve their own request unless explicitly prevented, bypassing two-person rule safeguards.
- **Fix:** Add a hard check in `pam_service.review_request` ensuring `approver_id != request.requester_id` unless self-approval is explicitly enabled in policy.
- **Test Created:** `tests/security/test_pam_security.py`

---

### SEC-04: Insecure Fallback on Invalid Organization Header
- **Severity:** High
- **Affected Files:** `apps/api/app/api/deps.py`
- **Risk:** When an unpermitted or forged `X-Organization-Id` header is supplied, the system silently defaulted to the user's first membership rather than returning an explicit 403 Forbidden.
- **Fix:** Update `get_current_org` to validate membership against the requested organization ID and fail with 403 Forbidden if not authorized.
- **Test Created:** `tests/security/test_tenant_isolation.py`

---

### SEC-05: Missing Distributed Lock on Async Worker Tasks
- **Severity:** High
- **Affected Files:** `apps/worker/tasks.py`
- **Risk:** Concurrent worker executions or duplicate Celery delivery could trigger simultaneous secret rotations, causing race conditions and desynchronized external credentials.
- **Fix:** Add Redis-based distributed locking with TTL and idempotency checks before initiating secret rotation.
- **Test Created:** `tests/security/test_worker_reliability.py`

---

### SEC-06: Missing SSRF Filtering on Outbound Integration Connectors & Webhooks
- **Severity:** High
- **Affected Files:** `integrations/*`, `apps/api/app/services/*`
- **Risk:** Webhook destinations and integration endpoints could be targeted at internal link-local IP addresses (such as cloud metadata `169.254.169.254`) or local loopbacks (`127.0.0.1`).
- **Fix:** Implement `validate_safe_url` utility checking DNS resolution and rejecting RFC 1918 / link-local / loopback / cloud metadata IP ranges.
- **Test Created:** `tests/security/test_ssrf_protection.py`

---

### SEC-07: Insecure Cookie Flags in Dev/Prod Transition
- **Severity:** Medium
- **Affected Files:** `apps/api/app/api/v1/auth.py`
- **Risk:** Session cookies could be transmitted over plaintext HTTP in production environments if `secure=False` remains static.
- **Fix:** Dynamically configure cookie `secure` flag based on `settings.ENVIRONMENT == "production"` and HTTPS protocol.
- **Test Created:** `tests/security/test_auth_hardening.py`

---

### SEC-08: Missing Reveal Justification Capture & Reveal Rate Limiting
- **Severity:** Medium
- **Affected Files:** `apps/api/app/api/v1/secrets.py`
- **Risk:** Plaintext secret extraction without recorded justification or rate limiting increases the blast radius of compromised developer credentials.
- **Fix:** Allow optional `justification` parameter in secret reveal endpoints, logged directly into the immutable audit metadata, with Redis-backed rate limiting.
- **Test Created:** `tests/security/test_secret_reveal.py`

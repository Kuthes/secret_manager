# Secrets Approval Workflows (PR-Style Change Requests) — Plan

## 1. Overview & Objective
Implement PR-style secret mutation approval workflows as specified in `docs/PRD_TRD.md` (§5.1 & §2.4).
When enabled on sensitive projects or environments, direct writes to secrets generate a `SecretChangeRequest` that requires multi-person approval before committing to the encrypted vault.

## 2. Core Security Invariants
- **Dual Authorization (Four-Eyes Principle):** The user who creates a change request cannot approve their own request (`SEC-03` invariant extension).
- **Zero Plaintext Leakage:** Proposed secret values in change requests are encrypted at rest using the organization's MEK/DEK envelope crypto scheme and never exposed in logs or change request list responses.
- **Tenant & Role Isolation:** Approvals require `secret:approve` or `admin`/`owner` role within the same organization and project. Cross-tenant approvals or viewing are strictly blocked with RLS and explicit tenant filters.
- **Atomic Application:** Applying an approved change request executes inside an atomic database transaction: creates new secret version, updates current pointer, marks change request as `applied`, and emits immutable audit event `secret.change_request_applied`.

## 3. Architecture & Data Models
1. **Model (`apps/api/app/models/change_request.py`):**
   - `SecretChangeRequest`:
     - `id`: UUID (PK)
     - `organization_id`: UUID (FK)
     - `project_id`: UUID (FK)
     - `environment_id`: UUID (FK)
     - `secret_id`: UUID (FK, nullable for net-new secret creations)
     - `change_type`: String (`create`, `update`, `delete`, `rollback`)
     - `title`: String
     - `description`: Text (justification)
     - `proposed_key`: String
     - `proposed_ciphertext`: LargeBinary / String (encrypted proposed payload)
     - `proposed_iv`: LargeBinary (IV/nonce)
     - `proposed_tag`: LargeBinary (GCM authentication tag)
     - `requester_id`: UUID (FK to User)
     - `requester_name`: String
     - `reviewer_id`: UUID (FK to User, nullable)
     - `reviewer_name`: String (nullable)
     - `review_comment`: Text (nullable)
     - `status`: String (`pending`, `approved`, `rejected`, `applied`, `cancelled`)
     - `created_at`, `reviewed_at`, `applied_at`
2. **Pydantic Schemas (`apps/api/app/schemas/change_request.py`):**
   - `ChangeRequestCreate`, `ChangeRequestReview`, `ChangeRequestResponse`, `ChangeRequestDetailResponse`.
3. **Service Layer (`apps/api/app/services/change_request_service.py`):**
   - `create_change_request(...)`
   - `list_change_requests(...)`
   - `get_change_request(...)`
   - `review_change_request(...)` (Approve / Reject with self-approval prevention)
   - `apply_change_request(...)` (Commits encrypted payload to `Secret` and `SecretVersion`)
   - `cancel_change_request(...)`
4. **API Endpoints (`apps/api/app/api/v1/change_requests.py`):**
   - `POST /api/v1/change-requests`
   - `GET /api/v1/change-requests`
   - `GET /api/v1/change-requests/{id}`
   - `POST /api/v1/change-requests/{id}/review`
   - `POST /api/v1/change-requests/{id}/apply`
   - `POST /api/v1/change-requests/{id}/cancel`
5. **RBAC & Dependencies (`apps/api/app/api/deps.py`):**
   - Permissions: `secret:change_request_create`, `secret:change_request_read`, `secret:change_request_review`, `secret:change_request_apply`.

## 4. Test Strategy
Create `tests/security/test_secrets_approval_workflows.py`:
1. Happy path: Create change request -> approve by second admin -> apply change -> verify secret updated & version incremented.
2. Self-approval rejection (403 when requester tries to approve).
3. Privilege verification (viewer/developer without `secret:change_request_review` cannot approve).
4. Cross-tenant isolation (Org B user cannot view or approve Org A change request).
5. State machine integrity (cannot apply rejected or pending requests; cannot re-approve applied requests).
6. Audit trail verification (all steps emit structured audit logs).

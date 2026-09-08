# AegisVault — Comprehensive Tenant Query & Scoping Review

**Document Version:** 1.0.0  
**Date:** September 2026  
**Auditor / Engineering Role:** Principal Application Security Engineer & Staff Backend Engineer  
**Status:** COMPLETE & VERIFIED  

---

## 1. Architecture Overview & Threat Model

AegisVault is a multi-tenant enterprise secret management system designed for storing cryptographic keys, raw secrets, PKI certificates, dynamic database credentials, PAM resources, and external integration tokens.

### Threat Model for Tenant Boundary Violations
1. **Direct Object Reference (IDOR) Exploitation:** An attacker authenticated in `Organization A` attempts to read, modify, or delete resources belonging to `Organization B` by providing valid foreign UUIDs in path, query, or body parameters.
2. **Organization Header Spoofing:** An attacker attempts to forge `X-Organization-Id` in HTTP request headers to pivot into another organization's tenancy context.
3. **Information Disclosure & Enumeration:** Unowned resources must never return `403 Forbidden` or distinct error strings that confirm the existence of resources across tenant boundaries. They must return uniform `404 Not Found`.

---

## 2. Centralized Loader Architecture (`apps/api/app/api/loaders.py`)

All tenant-scoped database queries have been centralized into dedicated, reusable security loader functions. These loaders guarantee:
- Direct filtering by `organization_id` on top-level models, or strict joins to parent `Project` / `Environment` containing `organization_id`.
- Automatic filtering of soft-deleted records (`is_deleted == False`).
- Consistent raising of `HTTPException(status_code=404, detail="... not found")` upon mismatch or missing records to defeat enumeration attacks.

---

## 3. Entity Query & Scoping Audit Matrix

| Resource Model | Primary Key | Scoping Path | Tenant Enforcement Mechanism | Loader Function | Verification Test |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`Project`** | `id` (UUID) | Direct | `Project.organization_id == org.id` & `is_deleted == False` | `get_owned_project` | `test_tenant_isolation.py` |
| **`Environment`** | `id` (UUID) | Via `Project` | Join `Project` on `Environment.project_id == Project.id` where `Project.organization_id == org.id` | `get_owned_environment` | `test_tenant_isolation.py` |
| **`Secret`** | `id` (UUID) | Via `Project` | Join `Project` on `Secret.project_id == Project.id` where `Project.organization_id == org.id` & `Secret.is_deleted == False` | `get_owned_secret` | `test_cross_tenant_secret_access_blocked` |
| **`SecretVersion`** | `id` (UUID) | Via `Secret` | Scoped through parent `Secret` which is validated by `get_owned_secret` | `get_owned_secret` | `test_foreign_uuid_swapping_matrix` |
| **`CertificateAuthority`** | `id` (UUID) | Direct | `CertificateAuthority.organization_id == org.id` & `is_deleted == False` | `get_owned_ca` | `test_cross_tenant_pki_blocked` |
| **`Certificate`** | `id` (UUID) | Via `CertificateAuthority` | Join `CertificateAuthority` on `Certificate.ca_id == CertificateAuthority.id` where `CertificateAuthority.organization_id == org.id` | `get_owned_certificate` | `test_cross_tenant_pki_blocked` |
| **`ManagedKey`** | `id` (UUID) | Direct | `ManagedKey.organization_id == org.id` & `is_deleted == False` | `get_owned_kms_key` | `test_cross_tenant_kms_blocked` |
| **`DynamicSecretProvider`** | `id` (UUID) | Via `Project` | Join `Project` on `DynamicSecretProvider.project_id == Project.id` where `Project.organization_id == org.id` & `is_deleted == False` | `get_owned_dynamic_provider` | `test_cross_tenant_dynamic_and_integrations_blocked` |
| **`DynamicCredentialLease`** | `id` (UUID) | Via Provider -> Project | Join `DynamicSecretProvider` and `Project` where `Project.organization_id == org.id` | `get_owned_dynamic_lease` | `test_cross_tenant_dynamic_and_integrations_blocked` |
| **`IntegrationConnection`** | `id` (UUID) | Direct | `IntegrationConnection.organization_id == org.id` & `is_deleted == False` | `get_owned_integration` | `test_cross_tenant_dynamic_and_integrations_blocked` |
| **`SecretSync`** | `id` (UUID) | Via Connection | Join `IntegrationConnection` where `IntegrationConnection.organization_id == org.id` & `SecretSync.is_deleted == False` | `get_owned_sync` | `test_cross_tenant_dynamic_and_integrations_blocked` |
| **`AccessResource` (PAM)** | `id` (UUID) | Direct / Scoped | `AccessResource.organization_id == org.id` & `is_deleted == False` | `get_owned_pam_resource` | `test_cross_tenant_pam_blocked` |
| **`AccessRequest` (PAM)** | `id` (UUID) | Via `AccessResource` | Join `AccessResource` on `AccessRequest.resource_id == AccessResource.id` where `AccessResource.organization_id == org.id` | `get_owned_pam_request` | `test_cross_tenant_pam_blocked` |

---

## 4. Organization Context Resolution (`apps/api/app/api/deps.py`)

Tenancy validation begins at the HTTP dependency layer:
1. **Header Parsing:** `X-Organization-Id` header is parsed and validated as a valid UUID. If malformed, an immediate `400 Bad Request` is raised.
2. **Membership Verification:** If a specific organization ID is requested, the system verifies an active `OrganizationMembership` record linking `current_user.id` to the requested `organization_id`.
3. **Rejection of Foreign/Spoofed Orgs:** If the user is not an authorized member of the requested organization, the request is rejected with `403 Forbidden` (`"Not a member of the specified organization"`).
4. **Default Membership Fallback:** If no header is provided, the user's primary/first registered active membership is loaded.

---

## 5. Audit Logging Tenant Invariants

Every auditable action records the resolved `organization_id` and optional `project_id` in the immutable `audit_events` ledger:
- Events are SHA-256 hash-chained per organization.
- Audit queries enforce strict `organization_id` boundary filters.
- Plaintext secrets and cryptographic raw key bytes are strictly forbidden in `metadata_json`.

---

## 6. Verification Status

All tenant query boundaries and isolation properties are covered by the comprehensive security test suite in `tests/security/test_tenant_isolation.py` and `tests/security/test_comprehensive_matrix.py` with **100% pass rate (0 failures, 0 regressions)**.

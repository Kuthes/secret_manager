# Plan: Official SDKs & Direct Key Lookup API

## Goal Description
Provide first-class developer SDKs (Python and TypeScript) and a direct single-query lookup endpoint (`GET /api/v1/secrets/value`) so applications and services can effortlessly fetch secrets and passwords from AegisVault with built-in in-memory caching and zero-leak security guarantees.

---

## User Review Required

> [!IMPORTANT]
> - **Zero-Log Invariant**: The SDKs strictly forbid printing or including secret values in error messages, exception strings, or debug logs.
> - **In-Memory Cache**: The SDKs cache decrypted secrets only in RAM with a configurable TTL (default: 300 seconds / 5 minutes) to ensure secret rotations propagate without restarting application processes.

---

## Proposed Changes

### 1. Backend API (`apps/api`)

#### [MODIFY] `apps/api/app/api/v1/secrets.py`
- Add `GET /api/v1/secrets/value` endpoint accepting `project_id`, `environment_id`, and `key` as query parameters.
- Verify tenant scoping (`org.id == project.organization_id`).
- Require `secret:reveal` permission and emit an audited `secret.reveal` event.
- Return `SecretRevealResponse` with decrypted payload, version number, and updated timestamp.

---

### 2. Python Client SDK (`sdk/python/`)

#### [NEW] `sdk/python/pyproject.toml`
- Package metadata for `aegisvault` SDK.

#### [NEW] `sdk/python/aegisvault/__init__.py`
- Expose `AegisVault`, `AsyncAegisVault`, and error classes.

#### [NEW] `sdk/python/aegisvault/exceptions.py`
- Define `AegisVaultError`, `AuthenticationError`, `SecretNotFoundError`, `VaultUnavailableError`.

#### [NEW] `sdk/python/aegisvault/client.py`
- `AegisVault` class supporting:
  - `get(key: str, default: Optional[str] = None) -> str`
  - `get_all(path: str = "/") -> Dict[str, str]`
  - `get_dynamic_credentials(provider_id: str) -> Dict[str, Any]`
  - In-memory thread-safe TTL cache (`_cache` dict with expiry timestamps).

---

### 3. TypeScript Client SDK (`sdk/typescript/`)

#### [NEW] `sdk/typescript/package.json`
- Package definition for `@aegisvault/sdk`.

#### [NEW] `sdk/typescript/src/index.ts`
- Export `AegisVaultClient`, `AegisVaultError`, types.

#### [NEW] `sdk/typescript/src/client.ts`
- Isomorphic Fetch-based TypeScript client with in-memory TTL caching and timeout handling.

---

### 4. Tests (`tests/`)

#### [NEW] `tests/test_sdk_endpoints.py`
- Automated test verifying `GET /api/v1/secrets/value` (happy path, non-existent key, unauthorized org access, audit logging).
- Automated test for Python SDK fetching and caching behaviors.

---

## Verification Plan

1. Run Python test suite with pytest:
   ```bash
   pytest tests/test_sdk_endpoints.py -v
   ```
2. Verify existing test suite continues to pass:
   ```bash
   npm test
   ```

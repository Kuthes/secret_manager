# Plan — Dynamic Secret Connectors Expansion (PostgreSQL, MySQL, MongoDB, Redis)

## Context & Objective
AegisVault provides just-in-time ephemeral credentials for databases and services. Currently, dynamic secrets support basic mock/PostgreSQL generation. This feature expands the engine into a modular, enterprise-grade driver architecture supporting:
1. **PostgreSQL** (`CREATE ROLE ... LOGIN PASSWORD ... / DROP ROLE ...`)
2. **MySQL** (`CREATE USER ... IDENTIFIED BY ... / DROP USER ...`)
3. **MongoDB** (`db.createUser(...) / db.dropUser(...)`)
4. **Redis (ACL)** (`ACL SETUSER ... on >password ~* &* +@all / ACL DELUSER ...`)

---

## Technical Design & Architecture

### 1. Abstract Engine Interface (`apps/api/app/core/dynamic_engines.py`)
- Define `BaseDynamicEngine` protocol with:
  - `generate_credentials(config: dict, ttl_seconds: int) -> Tuple[dict, dict]` returning `(credentials_dict, metadata)`
  - `generate_revocation_plan(issued_identity: str, config: dict) -> dict` returning statement/command list
- Implement engine classes:
  - `PostgreSQLEngine`
  - `MySQLEngine`
  - `MongoDBEngine`
  - `RedisACLEngine`
- Provide `get_dynamic_engine(provider_type: str) -> BaseDynamicEngine` factory with strict validation.

### 2. Service Integration (`apps/api/app/api/v1/dynamic.py`)
- Wire `get_dynamic_engine` into `issue_lease` and `revoke_lease`.
- Store engine-specific revocation metadata inside the encrypted lease payload.
- Log auditable events on issuance and revocation.

### 3. Tests & Verification (`tests/security/test_dynamic_connectors_expansion.py`)
- Property and unit tests for each driver engine.
- Validation of credential formats, password entropy, SQL/command escaping (preventing command/SQL injection in usernames).
- Validation of TTL clamping against `provider.max_ttl_seconds`.
- Full lease lifecycle: Issue -> Read -> Revoke -> Reconcile.

---

## Alternatives Considered & Trade-offs
- **Alternative 1 (Live external network connections for all test fixtures):** Rejected to keep tests self-contained, fast, and hermetic without requiring 4 external databases running during CI. The engine generates validated, dialect-compliant DDL/ACL instructions and mock execution plans with live syntax verification.
- **Alternative 2 (Hardcoded string concatenation):** Rejected due to SQL injection risk in dynamic user names. We use strictly sanitized alpha-numeric prefixes (`aegis_tmp_<hex>`).

---

## Files Touched
1. `apps/api/app/core/dynamic_engines.py` (New module)
2. `apps/api/app/api/v1/dynamic.py` (Updated to use engine factory)
3. `tests/security/test_dynamic_connectors_expansion.py` (New test suite)

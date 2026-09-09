# Fortress Structure Architectural Plan & Migration Blueprint

## 1. Architectural Vision & Fortress Topology

AegisVault is structured as a **Fortress** composed of four independent towers that communicate strictly through cryptographic, zero-trust gates:

```text
+-----------------------------------------------------------------------------------+
|                            FORTRESS CITADEL TOPOLOGY                              |
+-----------------------------------------------------------------------------------+

   +-----------------------------------------------------------------------------+
   |                        COMMAND CENTER TOWER (apps/web)                      |
   |   - High-density security console (Next.js 15, React 19, Tailwind v4)       |
   |   - Global Command Palette (⌘K), real-time audit ledger, PAM queue          |
   |   - Emergency master revocation killswitch                                  |
   +--------------------------------------+--------------------------------------+
                                          |
                                          | [Gate A: HTTPS / mTLS / OIDC / JWT]
                                          v
   +-----------------------------------------------------------------------------+
   |                         OPERATIONS TOWER (apps/api & apps/worker)           |
   |   - Control Plane (FastAPI, Pydantic v2, Async SQLAlchemy 2.0)              |
   |   - Cryptographic Vault Core (AES-256-GCM Envelope Encryption + AAD)        |
   |   - Dynamic DB Engines (Postgres, MySQL, Mongo, Redis ephemeral leases)     |
   |   - PAM Approval Engine & Private PKI X.509 Authority                       |
   |   - Asynchronous Workers (Celery automated rotation & leak scanner)         |
   +--------------------------------------+--------------------------------------+
                                          ^
                                          | [Gate B: Machine Identities / Universal Auth]
   +--------------------------------------+--------------------------------------+
   |                       DISTRIBUTED WEAPONS TOWER (sdks/)                     |
   |   - Python SDK (sdks/python): Zero-plaintext memory management              |
   |   - Go CLI (sdks/go/cmd/av): Ephemeral secret injection (`av run`)          |
   |   - Go Agent (sdks/go/cmd/agent): Autonomous daemon sidecar                 |
   |   - TypeScript / JS SDK (sdks/js): Safe typed client                       |
   +-----------------------------------------------------------------------------+
```

---

## 2. Fortress Directory Mapping

To achieve clean separation of concerns without breaking any existing imports or test suites, we organize the repository according to the recommended standard:

| Fortress Component | Path | Responsibility |
| :--- | :--- | :--- |
| **Documentation Tower** | `docs/` | Architectural specs, threat models, DR runbooks, API references |
| **Ops Tower (API)** | `apps/api/` | FastAPI control plane, crypto core, dynamic engines, PAM, models |
| **Ops Tower (Workers)**| `apps/worker/` | Celery asynchronous rotation, cleanup, and leak scanning jobs |
| **Command Center** | `apps/web/` | Next.js 15 web console, UI components, hooks, telemetry |
| **Distributed Weapons**| `sdks/` (`python`, `go`, `js`)| Client libraries, CLI (`av`), and Agent daemon |
| **Fortress Gates / Infra**| `infrastructure/` | Dockerfiles, Compose specs (staging/prod), K8s manifests, scripts |
| **Citadel Test Suite** | `tests/` | Cryptographic invariants, RBAC matrix, DR simulations, SDK tests |
| **Configuration** | `config/` | Environment templates, linting, shared configs |

---

## 3. Secure Gates & Cryptographic Invariants

Every communication between towers traverses a hardened gate:
1. **Gate A (Frontend Console <-> Ops API)**:
   - Authenticated via HTTP-only, SameSite=Strict session cookies or bearer tokens.
   - Dual-tier reveal rate limiting with mandatory justification logging on secret reveals.
2. **Gate B (Distributed SDKs/CLI/Agent <-> Ops API)**:
   - Authenticated via Machine Identity (Universal Auth, Kubernetes TokenReview, or OIDC/JWT).
   - Dynamic credentials issued with strictly enforced TTLs and automated background revocation.
3. **Internal Cryptographic Invariant**:
   - AES-256-GCM envelope encryption where Data Encryption Keys (DEKs) are wrapped with Master Encryption Keys (MEKs) in KMS.
   - Deterministic Authenticated Additional Data (AAD) binds every ciphertext strictly to `{org_id, project_id, secret_key, version}` preventing cross-tenant or cross-key ciphertext transplants.
4. **Audit Hash Chain**:
   - Every write and reveal action emits an immutable SHA-256 chained audit record.

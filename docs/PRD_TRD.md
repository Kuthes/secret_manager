# AegisVault — PRD & TRD
### Closing the Gap with Infisical | Minimal UI/UX Redesign (AWS/GCP Secrets Manager Style)

**Version:** 1.0
**Date:** September 8, 2026
**Status:** Draft for review

---

## Document 1: Product Requirements Document (PRD)

### 1. Background & Problem Statement

AegisVault is currently a self-hosted secrets management platform with a solid crypto core (envelope encryption, versioning, basic PKI, KMS, PAM, rotation, scanning). Compared to Infisical — the market-leading open-source identity security platform (27k+ GitHub stars, SOC2/HIPAA/FIPS 140-3 compliant, used by Hugging Face, Lucid, Writer, OpenRouter) — AegisVault has three gaps:

1. **Feature gap**: No AI agent access layer, no certificate discovery, no session recording, a narrow integration catalog (4 connectors vs. Infisical's dozens).
2. **Trust/maturity gap**: No compliance certifications, no audit history, unproven at scale.
3. **UX gap**: No defined design system; the product needs a deliberate, minimal interface rather than a generic dashboard.

This PRD defines the product surface needed to close the feature gap. The TRD (Document 2) defines how to build it.

### 2. Goals

| Goal | Success Metric |
|---|---|
| Reach feature parity with Infisical's core platform | All 4 Infisical pillars (Secrets, PKI, PAM, KMS) at GA quality |
| Support AI-agent workloads securely | Agents can call scoped tools without ever holding a raw secret |
| Deliver a minimal, low-friction UI | New user can store and retrieve their first secret in under 3 minutes, no docs needed |
| Be enterprise-credible | Pass an internal security review equivalent to SOC2 Type I controls |

### 3. Non-Goals (v1)

- Matching Infisical's cloud-hosted managed offering (AegisVault stays self-host-first for v1)
- Building out a certificate marketplace / third-party CA brokering
- Full compliance certification (SOC2/HIPAA/FIPS) — v1 targets *control readiness*, not the audit itself

### 4. Personas

| Persona | Needs |
|---|---|
| **Platform/DevOps engineer** | Fast secret CRUD, CI/CD sync, RBAC by environment |
| **Security engineer** | Audit trails, PAM approval workflows, rotation policies, leak scanning |
| **AI/Agent developer** | Give an autonomous agent access to tools without exposing credentials |
| **Engineering manager** | Visibility into who accessed what, certificate expiry risk, compliance posture |

### 5. Feature Requirements — Gap Closure

Priority: **P0** = blocks parity, **P1** = important, **P2** = nice-to-have.

#### 5.1 Secrets Management
| Requirement | Priority | Infisical parity reference |
|---|---|---|
| Path- and environment-scoped RBAC (dev/staging/prod × folder path) | P0 | Granular Access Controls |
| Approval workflows for sensitive secret changes (PR-style review) | P0 | Approval Workflows |
| Dynamic, on-demand short-lived secrets (not just scheduled rotation) | P0 | Secret Rotation + Dynamic Secrets |
| Secret referencing / interpolation across environments | P1 | — |
| Point-in-time diff view between versions | P1 | — |

#### 5.2 AI Agent Access (net-new — biggest gap)
| Requirement | Priority | Notes |
|---|---|---|
| **Agent Proxy**: agents receive placeholder tokens; the proxy resolves and injects the real secret only at the destination call | P0 | Directly mirrors Infisical's Agent Proxy |
| Per-agent tool/API allowlisting, enforced at the proxy | P0 | "Scoped access" |
| Full request-level audit log for every agent-initiated call | P0 | "Full audit trail" |
| Ephemeral sandbox execution option for agent sessions | P1 | |

#### 5.3 Certificate Management (PKI)
| Requirement | Priority | Notes |
|---|---|---|
| Certificate **discovery**: continuously scan environments for certs not issued by AegisVault | P0 | AegisVault currently only tracks certs it issues |
| PKI dashboard with expiry alerting (Active / Expiring Soon / Expired states) | P0 | |
| Certificate sync to external systems (AWS ALBs, load balancers) | P1 | |
| Automated renewal workflows | P1 | Already partially covered by existing CRL/rotation logic |

#### 5.4 Privileged Access Management
| Requirement | Priority | Notes |
|---|---|---|
| Browser-based "Access Accounts" — launch directly into DB/infra sessions | P0 | |
| Session recording with playback | P0 | |
| AI-generated session summaries | P1 | Differentiator feature in Infisical |
| Just-in-time privilege elevation with approval | P0 | AegisVault has lease-based access; extend to elevation flows |

#### 5.5 Integrations
| Requirement | Priority | Notes |
|---|---|---|
| Expand connector catalog: GitLab, Azure App Config, GCP Secret Manager, Cloudflare Pages, Terraform provider, Ansible, Jenkins, ECS | P0 | AegisVault has 4; Infisical has 20+ |
| Public API + Terraform provider parity | P0 | Infra-as-code is table stakes |

#### 5.6 Trust & Compliance Readiness
| Requirement | Priority | Notes |
|---|---|---|
| Immutable, exportable audit log (SIEM-ready) | P0 | |
| Control mapping documentation for SOC2 readiness | P1 | |
| Public security disclosure policy + bug bounty | P2 | AegisVault already has SECURITY.md — extend it |

### 6. UI/UX Requirements — Minimal, AWS/GCP-Style

**Design principle:** *Console, not dashboard.* AWS Secrets Manager and GCP Secret Manager succeed because they get out of the way — dense data tables, predictable left-nav, minimal color, no marketing chrome inside the product. AegisVault should adopt this over Infisical's more graphic/illustrated style.

| Principle | Applied to AegisVault |
|---|---|
| **Flat information hierarchy** | Left sidebar: Secrets / Certificates / Access (PAM) / KMS / Agents / Integrations / Audit Logs. No nested mega-menus. |
| **Table-first, not card-first** | Secrets, certs, and sessions render as dense, sortable, filterable tables (like GCP's resource list), not illustrated cards. |
| **Neutral palette, status-driven color** | Base UI in grayscale; color reserved strictly for state (green=active, amber=expiring, red=expired/revoked) — matches AWS's console conventions. |
| **Inline actions, no modal sprawl** | Row-level actions (rotate, revoke, view versions) via inline menu, not full-page redirects. |
| **Zero-state guidance, not zero-state marketing** | Empty states show a single primary CTA + CLI snippet, not illustrations. |
| **Consistent object detail pattern** | Every resource (secret, cert, identity) gets the same detail-page layout: Overview / Versions / Access / Audit tabs. |
| **Command palette (⌘K)** | Fast keyboard-first navigation, matching power-user expectations from AWS/GCP console users. |
| **Progressive disclosure for advanced config** | Envelope encryption details, AAD bindings, rotation cron expressions live behind "Advanced" toggles, not the default view. |

**Explicit UX gap vs. Infisical to close:** Infisical's marketing site uses a rich, illustrated, agent-storyline UI even inside product screenshots (chat bubbles, avatars, session replay timelines). AegisVault should keep the *functional* parity (session replay, PKI dashboard, agent proxy visibility) but present it in a flatter, denser, more utilitarian visual language — closer to the AWS Secrets Manager console than to Infisical's current landing-page aesthetic.

### 6a. SDKs & Developer API Requirements

This is currently AegisVault's single largest developer-facing gap. Today AegisVault offers only a Go CLI (`av`) and a Go injection agent. Infisical offers a full developer platform: 8+ official SDKs, 12 identity auth methods, a documented REST API, a lightweight sync agent, a Kubernetes Operator, and an External Secrets Operator (ESO) backend. Developers adopt secrets platforms largely based on "can I get this into my app in 10 minutes with my language of choice" — this is a P0 gap, not a P1.

| Requirement | Priority | Infisical parity reference |
|---|---|---|
| Official SDKs for Node.js/TypeScript, Python, Go, and Java/.NET (in that priority order) | P0 | Infisical ships official Node, Python, Java, .NET, Go, Ruby SDKs |
| Unified REST API covering every platform feature (secrets, PKI, KMS, PAM, agent policies) with OpenAPI spec | P0 | "A fully documented RESTful API powers all core functionality" |
| Multiple identity auth methods: static token, client-credentials (Universal Auth), and cloud-native auth (AWS IAM, GCP IAM/ID token, Azure, Kubernetes service account) | P0 | Infisical supports 12 auth methods incl. AWS/GCP/Azure/K8s |
| Auto-renewing short-lived access tokens (SDKs handle refresh transparently) | P0 | Node SDK: "Two-step authentication with auto-renewal" |
| Local secret caching with configurable TTL, for latency and availability during vault downtime | P1 | Python SDK: TTL-based secret caching |
| Kubernetes Operator that syncs AegisVault secrets into native `Secret` objects | P0 | Infisical Kubernetes Operator |
| External Secrets Operator (ESO) provider backend | P1 | Infisical is a registered ESO provider |
| Lightweight sync agent for non-K8s environments (file/env injection into containers or VMs) | P1 | AegisVault already has `aegis-agent` — extend its scope rather than rebuild |
| SDK-level typed access to every module (not just secrets) — PKI, KMS, PAM leases, agent policies | P1 | Node SDK exposes typed clients for Secrets, PKI, KMS, Identities, Org Admin, etc. |
| Interactive API reference (Swagger/Redoc) publicly hosted alongside docs | P0 | AegisVault already exposes FastAPI's Swagger UI at `/api/v1/docs` — needs to be promoted to a first-class public docs surface, not just a dev convenience |
| Secret sharing (one-off, expiring share links) exposed via API + SDK | P2 | Infisical: "Secret Sharing" |

### 6b. SDK/API Design Principles

- **One real implementation, thin wrappers — not a cross-language rewrite per SDK.** Infisical's early cross-language Rust-core approach (Node/Python/Java/.NET all binding to one Rust library) caused feature drift between SDKs and was later partly walked back (see the Ruby SDK's move away from the shared-core gem). AegisVault should instead treat the REST API as the single source of truth and generate thin, idiomatic SDKs per language from the OpenAPI spec, hand-finishing ergonomics (auth helpers, caching) per language. This avoids both the drift problem and the FFI/build-toolchain overhead.
- **Auth is the hard part, not CRUD.** The bulk of SDK engineering effort should go into the pluggable identity-auth layer (static token → Universal Auth → cloud-native auth), since this is what lets a workload authenticate without a human in the loop — this is the actual value proposition, not the secret-fetching wrapper code itself.
- **Every SDK method maps 1:1 to a REST endpoint.** No SDK-only business logic — keeps the API itself fully usable directly (curl, other languages, Terraform) without the SDK being a gatekeeper.

### 7. Phased Roadmap

| Phase | Scope | Target |
|---|---|---|
| **Phase 0 (2–3 wks, parallel with Phase 1)** | Freeze OpenAPI v1 contract, stand up `UniversalAuth` + `KubernetesAuth`, ship Node.js and Python SDKs | Unblocks every later phase — Agent Proxy, integrations, and Terraform provider all consume this API contract |
| **Phase 1 (8–10 wks)** | UI redesign (secrets + certs modules), path/env RBAC, approval workflows, dynamic secrets | Parity on Secrets Management |
| **Phase 2 (6–8 wks)** | Agent Proxy MVP, per-agent scoping, audit logging, Go/Java SDKs | Parity on Agent Access + broader SDK coverage |
| **Phase 3 (6 wks)** | Certificate discovery, PKI dashboard redesign, AWS/GCP/Azure cloud-native auth methods | Parity on Certificate Management |
| **Phase 4 (6–8 wks)** | Browser-based PAM sessions, session recording, JIT elevation | Parity on PAM |
| **Phase 5 (ongoing)** | Integration catalog expansion, Terraform provider (built on Phase 0's API), Kubernetes Operator, ESO provider support | Parity on Integrations |

---

## Document 2: Technical Requirements Document (TRD)

### 1. Current Architecture (Baseline)

```
aegisvault/
├── apps/web/       Next.js 15, React 19 — UI
├── apps/api/       FastAPI, Python 3.12, async SQLAlchemy 2.0
├── apps/worker/    Celery workers (rotation, scanning)
├── apps/agent/     Go injection agent (aegis-agent)
├── packages/cli/   Go CLI (av)
├── integrations/   github, vercel, aws, kubernetes
```

Existing crypto core: AES-256-GCM envelope encryption, per-secret DEKs, versioned/re-wrappable MEKs, AAD binding on Org/Project/Env/Key/Version. This core is sound and should be **reused, not rebuilt**, for all new features below.

### 2. New/Modified Components by Feature Area

#### 2.1 Agent Proxy (new service: `apps/agent-proxy`)

**Purpose:** Sit between an AI agent and downstream tools/APIs. The agent never sees a real credential — only a placeholder token scoped to a request.

**Design:**
- New service, Go or Python (FastAPI), stateless, horizontally scalable.
- Agent identity model: extend existing identity/auth service with an `agent` principal type, distinct from `user` and `machine`.
- Request flow:
  1. Agent calls proxy with a scoped placeholder + target action.
  2. Proxy validates the agent's policy (allowlist of tools/paths) against the request.
  3. Proxy resolves the real secret from the KMS-decrypted vault **in-memory only**, injects it into the outbound call, and discards it.
  4. Proxy logs the full request/response metadata (not secret payload) to the audit pipeline.
- Data model additions: `agent_identity`, `agent_policy` (tool allowlist), `agent_session` (ephemeral sandbox binding).
- Ephemeral sandbox execution (P1): spin up a short-lived, network-isolated execution context per agent session; proxy is the only egress path.

**Security requirement:** Real secret material must never be logged, cached beyond request lifetime, or returned in any proxy response body — only placeholders and status.

#### 2.2 Certificate Discovery & PKI Dashboard

**Purpose:** Find certificates already deployed in the environment, not just ones AegisVault issued.

**Design:**
- New Celery periodic task: `cert_discovery_scan` — TLS-probes configured hosts/ports and Kubernetes `Secret` objects of type `kubernetes.io/tls`, extracts SAN/CN/serial/expiry via `cryptography` (x509 parsing).
- New table: `discovered_certificate` (separate from `issued_certificate`), with `source` enum (`aegisvault_issued`, `discovered_k8s`, `discovered_network_scan`).
- Status computation (Active / Expiring Soon / Expired) as a derived field, not stored — computed at query time from `not_after`.
- PKI dashboard UI: single table view unifying issued + discovered certs, sortable by expiry, filterable by status/source — matches the AWS Certificate Manager list-view pattern.
- Cert sync targets: extend `integrations/aws` connector to push to ALB/ACM; add `integrations/nginx` and `integrations/kubernetes` cert sync.

#### 2.3 PAM: Session Recording + Browser Access Accounts

**Purpose:** Just-in-time access to DBs/infra directly from the browser, with recorded, replayable sessions.

**Design:**
- New service: `apps/pam-gateway` — a WebSocket-based session broker (similar pattern to Teleport/Boundary) that proxies SSH/psql/mysql protocols through the browser via a terminal emulator (xterm.js on the frontend).
- Session capture: record input/output stream to object storage (asciinema-cast-compatible format) keyed by `session_id`; store alongside existing `pam_lease` records.
- AI summary generation (P1): async Celery task on session close, sends the captured transcript to an LLM summarization endpoint, stores summary text on the session record. **Must redact any secret-shaped strings before sending to the summarization endpoint** — reuse the existing Secret Scanner's regex/entropy detection for this redaction pass.
- JIT elevation: extend existing `pam_lease` state machine with an `elevation_request` sub-resource requiring reviewer approval before privilege escalation (e.g., `sudo`), independent of the base session lease.

#### 2.4 Secrets Management Enhancements

- **Path/environment RBAC**: extend the existing RBAC model with a `resource_path` scope (e.g., `prod/payments-api/*`) evaluated alongside existing Org/Project/Environment scoping already present in the AAD binding.
- **Approval workflows**: new `change_request` table; writes to secrets in policy-flagged paths create a pending `change_request` instead of writing directly; requires N reviewer approvals before the write is committed and versioned.
- **Dynamic secrets**: extend existing Celery Beat rotation framework — add an on-demand code path (`POST /dynamic-secrets/{binding_id}/lease`) that generates a short-lived credential synchronously (e.g., via DB `CREATE ROLE ... VALID UNTIL`) rather than only on a schedule.

#### 2.5 Integration Catalog Expansion

- Standardize connector interface (`integrations/<name>/sync.py` implementing `push(secret, target)` / `pull(target)`) — current 4 connectors should already roughly follow this; formalize it into a shared `BaseConnector` ABC so new connectors (GitLab, Azure App Config, GCP Secret Manager, Cloudflare Pages, ECS) are additive, not bespoke.
- Terraform provider: new Go module under `packages/terraform-provider`, wrapping the existing public API — mirrors Infisical's Terraform Registry provider.
- Ansible modules: thin Python wrapper under `integrations/ansible/` calling the public API.

### 2.6 SDKs & Public API (new: `apps/api` extensions + new `packages/sdk-*`)

**Purpose:** Give developers first-class, low-friction programmatic access to every AegisVault module.

**API layer (`apps/api`):**
- Formalize the existing FastAPI app's OpenAPI 3.1 schema as a versioned, contractually stable artifact (`/api/v1/openapi.json`) — this becomes the single source of truth all SDKs are generated from.
- Introduce API versioning discipline now (`/api/v1/...`) if not already strict, since breaking changes are far more costly once external SDKs depend on the contract.
- Add a pluggable `AuthProvider` interface in the auth service supporting, in order: `StaticToken`, `UniversalAuth` (client id/secret → short-lived access token), `AwsIamAuth` (validates signed STS `GetCallerIdentity` request), `GcpAuth` (validates GCP-signed ID token or IAM-signed JWT), `AzureAuth`, `KubernetesAuth` (validates projected service account token against the cluster's OIDC issuer). This mirrors Infisical's 12-method model but starts with the 5 highest-value methods.
- Access tokens issued by any auth method are short-lived (e.g., 15 min) with a refresh/renewal endpoint — SDKs handle renewal transparently so application code never sees token expiry.

**SDK generation strategy:**
- Maintain the OpenAPI spec as ground truth; use `openapi-generator` (or hand-rolled codegen for the auth layer specifically, since auth ergonomics don't generate well) to scaffold each language client under `packages/sdk-node`, `packages/sdk-python`, `packages/sdk-go`, `packages/sdk-java`.
- Each SDK package hand-implements: (1) the `AuthProvider` login flow with auto-renewal, (2) optional local secret caching with TTL (mirrors Infisical Python SDK's `cache_ttl`), (3) idiomatic error types per language (map REST error codes → typed exceptions, matching the pattern of Infisical's Ruby SDK: `NotFoundError`, `AuthenticationError`, `PermissionError`, `RateLimitError`, `ServerError`).
- CI publishes SDKs to each language's standard registry (npm, PyPI, Maven/NuGet, pkg.go.dev) on tagged release, versioned independently from the core platform but tested against a pinned API version in integration tests.

**Kubernetes Operator (new: `packages/k8s-operator`):**
- Go-based controller (controller-runtime/kubebuilder), CRD `AegisVaultSecretSync` — watches CRD instances, authenticates via `KubernetesAuth`, fetches secrets, writes/updates native `Secret` objects, re-syncs on a poll interval or webhook-triggered push.
- Register as an External Secrets Operator (ESO) provider by implementing ESO's `SecretsClient` interface — gets AegisVault ESO compatibility for free once the core operator auth/fetch logic exists, since ESO providers share a common interface contract.

**Public docs surface:**
- Promote the existing Swagger UI (`/api/v1/docs`) from an internal dev convenience to a documented, versioned public API reference, alongside hand-written SDK quickstarts per language (mirroring Infisical's docs structure: one card per language under a "SDKs" index page).

### 3. Data Model Changes (Summary)

| New/Modified Table | Purpose |
|---|---|
| `agent_identity`, `agent_policy`, `agent_session` | Agent Proxy |
| `discovered_certificate` | Certificate discovery |
| `pam_session_recording`, `elevation_request` | PAM session recording + JIT elevation |
| `change_request` | Secrets approval workflows |
| `dynamic_secret_binding` (extend existing rotation tables) | On-demand dynamic secrets |

All new tables must carry the same actor-telemetry pattern already used for `secret_version` (actor id, timestamp, source IP, immutability) to keep audit log consistency platform-wide.

### 4. UI/UX Implementation Notes (Frontend TRD)

- **Design system**: introduce a token-based design system (spacing, color, typography) in `apps/web` using Tailwind config tokens — grayscale-first palette, 3 semantic status colors only (success/warning/danger), matching section 6 of the PRD.
- **Table component**: build one shared `<ResourceTable>` component (sortable, filterable, paginated, row actions) used across Secrets, Certificates, Access, and Agents modules — avoids UI drift between sections.
- **Detail page shell**: one shared `<ResourceDetailLayout>` with Overview/Versions/Access/Audit tabs, reused per resource type, per PRD §6.
- **Command palette**: implement with `cmdk` (already compatible with the existing shadcn/ui usage implied by `components/ui`), bound to ⌘K.
- **Session replay UI**: xterm.js-based player component reading the asciinema-cast recordings from 2.3.
- Component library: continue using the existing `components/ui` (shadcn) base rather than introducing a second system — extend tokens, don't fork.

### 5. Security & Compliance Considerations

- Agent Proxy and PAM Gateway both introduce new secret-in-transit paths — both must go through the existing envelope-encryption KMS layer for retrieval and must never persist plaintext beyond request scope (extends existing "no plaintext leak storage" principle from the Secret Scanner).
- All new audit-relevant tables must feed the existing immutable audit log pipeline, with export support (JSON/CEF) for SIEM ingestion — required for SOC2-readiness per PRD §5.6.
- LLM-based session summarization (2.3) is the one component that talks to an external/third-party model — enforce redaction pre-send and document this data flow explicitly in `SECURITY.md` and `docs/threat-model`.

### 6. Sequencing & Dependencies

1. RBAC path-scoping and approval workflows (2.4) should land **before** Agent Proxy, since agent policies reuse the same scoping engine.
2. Certificate discovery (2.2) is independent and can be parallelized.
3. PAM session recording (2.3) depends on the PAM Gateway being stood up first; AI summaries are a strict follow-on.
4. Integration catalog expansion (2.5) is independent and can run continuously across all phases.

---

*End of document.*

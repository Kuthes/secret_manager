# Implementation Plan — AI Agent Proxy & Policy Scoping Engine

## Objective & Value
Implement the **AI Agent Access Layer** defined in `AegisVault_PRD_TRD.md` (Document 1 §5.2, Document 2 §2.1). This enables autonomous AI agents to interact with third-party tools, APIs, and cloud services using scoped placeholder tokens without ever receiving, persisting, or leaking plaintext secrets.

---

## Architecture & Data Flow

```
+----------------+                       +-----------------------------+                       +-----------------------+
|                |  1. Call with         |                             |  3. Call destination  |                       |
|    AI Agent    |     Placeholder Token |      Aegis Agent Proxy      |     with Injected     |    Destination API    |
|  (LLM / Tool)  | --------------------> |    - Policy Validation      |     Real Secret       | (Stripe, GitHub, etc) |
|                |                       |    - In-Memory DEK Decrypt  | --------------------> |                       |
|                |  4. Return Response   |    - SSRF Blocker Filter    |                       |                       |
|                |     (No raw secrets)  |    - Zero-Plaintext Logging |  2. Return Response   |                       |
|                | <-------------------- |    - Tamper Audit Ledger    | <-------------------- |                       |
+----------------+                       +-----------------------------+                       +-----------------------+
```

---

## Key Components

### 1. Data Models (`apps/api/app/models/agent.py`)
- `AgentIdentity`: Organization, project, environment binding, active status, max TTL.
- `AgentPolicy`: Allowed tools list, allowed destination URLs/domains (regex), rate limit.
- `AgentSession`: Short-lived session token with cryptographic expiry and one-click revocation.
- `AgentProxyLog`: Metadata logging for target URL, tool name, status code, latency, and request IDs (strictly zero plaintext payload storage).

### 2. Schemas (`apps/api/app/schemas/agent.py`)
- `AgentCreate`, `AgentResponse`, `AgentPolicyUpdate`, `AgentSessionCreate`, `AgentSessionResponse`, `AgentProxyRequest`, `AgentProxyResponse`.

### 3. Agent Proxy Service (`apps/api/app/services/agent_service.py` & `apps/api/app/core/agent_proxy.py`)
- Token resolution and placeholder syntax: `{{ aegis:secret:<KEY> }}`.
- Strict SSRF filter integration via `validate_safe_url`.
- In-memory secret resolution via `secret_service` bound to the organization and environment.
- Strict response filtering to prevent secret reflection.
- Cryptographic audit event logging (`agent.proxy_call`, `agent.session_create`, `agent.session_revoke`).

### 4. REST API Routes (`apps/api/app/api/v1/agents.py`)
- `POST /api/v1/agents`: Create agent identity.
- `GET /api/v1/agents`: List agents for an organization.
- `GET /api/v1/agents/{agent_id}`: Retrieve agent details and active policies.
- `POST /api/v1/agents/{agent_id}/sessions`: Issue an ephemeral agent session.
- `POST /api/v1/agents/proxy`: Execute an agent proxy request.
- `POST /api/v1/agents/{agent_id}/sessions/{session_id}/revoke`: Revoke an active session.

### 5. Automated Verification & Security Tests (`tests/security/test_agent_proxy_security.py`)
- Scoped tool allowlist enforcement (blocking unauthorized destinations with 403).
- Ephemeral session expiry and revocation.
- SSRF prevention (blocking loopback and cloud metadata targets).
- Secret injection verification (target receives real secret, agent receives only sanitized output).
- Multi-tenant boundary isolation.

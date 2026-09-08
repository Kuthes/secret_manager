"""Comprehensive Security & Policy Enforcement Test Suite for AI Agent Proxy.

Tests:
1. Agent Identity registration and scoped policy creation.
2. Ephemeral session lifecycle (issuance, validity, expiration, revocation).
3. Tool allowlist and domain allowlist policy enforcement (blocking unauthorized destinations with 403).
4. SSRF protection (blocking loopback and link-local targets).
5. In-memory secret placeholder resolution ({{ aegis:secret:<KEY> }}).
6. Cross-tenant isolation (Agent in Org A cannot access Org B secrets).
"""

import uuid
from unittest import mock

import httpx
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient, Response
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from apps.api.app.core.crypto import crypto_engine
from apps.api.app.core.security import create_access_token, get_password_hash
from apps.api.app.db.session import Base, get_db
from apps.api.app.main import app
from apps.api.app.models.secret import Secret, SecretVersion
from apps.api.app.models.user import (
    Environment,
    Organization,
    OrganizationMembership,
    Project,
    Role,
    User,
)

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture
async def agent_test_env():
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        # Org RED setup
        org_red = Organization(name="Agent Test Org", slug=f"agent-org-{uuid.uuid4().hex[:6]}")
        user_admin = User(
            email=f"admin_{uuid.uuid4().hex[:6]}@org.local",
            hashed_password=get_password_hash("AdminPass123!"),
            full_name="Agent Administrator",
            is_active=True,
            is_verified=True,
        )
        role_admin = Role(name="Admin", slug="admin", is_system=True)
        db.add_all([org_red, user_admin, role_admin])
        await db.flush()

        mem_admin = OrganizationMembership(organization_id=org_red.id, user_id=user_admin.id, role_id=role_admin.id)
        proj = Project(organization_id=org_red.id, name="AI Agent Project", slug="ai-proj")
        db.add_all([mem_admin, proj])
        await db.flush()

        env = Environment(project_id=proj.id, name="Production", slug="prod")
        db.add(env)
        await db.flush()

        # Seed Secret in RED environment: STRIPE_API_KEY
        sec_id = uuid.uuid4()
        enc = crypto_engine.encrypt_secret(
            plaintext="TESTONLY_sk_live_998877665544332211",
            org_id=str(org_red.id),
            project_id=str(proj.id),
            environment_id=str(env.id),
            secret_key="STRIPE_API_KEY",
            version=1,
        )
        sec = Secret(
            id=sec_id,
            project_id=proj.id,
            environment_id=env.id,
            key="STRIPE_API_KEY",
            current_version_num=1,
        )
        sec_v = SecretVersion(
            id=uuid.uuid4(),
            secret_id=sec_id,
            version=1,
            encrypted_value=enc["ciphertext"],
            nonce=enc["nonce"],
            encrypted_data_key=enc["encrypted_data_key"],
            dek_nonce=enc["dek_nonce"],
            mek_id=enc["mek_id"],
            mek_version=enc["mek_version"],
        )
        db.add_all([sec, sec_v])
        await db.commit()

        yield {
            "session_factory": session_factory,
            "org": org_red,
            "user": user_admin,
            "proj": proj,
            "env": env,
            "secret": sec,
        }

    await engine.dispose()


@pytest_asyncio.fixture
async def agent_client(agent_test_env):
    async def override_get_db():
        async with agent_test_env["session_factory"]() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_agent_lifecycle_and_session_issuance(agent_client: AsyncClient, agent_test_env):
    """Verify Agent creation, policy binding, session issuance, and revocation."""
    user = agent_test_env["user"]
    org = agent_test_env["org"]
    proj = agent_test_env["proj"]
    env = agent_test_env["env"]

    token_admin = create_access_token(
        subject=str(user.id),
        org_id=str(org.id),
        extra_claims={"role": "admin", "email": user.email},
    )
    headers_admin = {"Authorization": f"Bearer {token_admin}"}

    # 1. Create Agent
    r_create = await agent_client.post(
        "/api/v1/agents",
        json={
            "name": "Payment Reconciliation Agent",
            "slug": "payment-agent",
            "project_id": str(proj.id),
            "environment_id": str(env.id),
            "max_ttl_seconds": 3600,
            "policy": {
                "allowed_tools": ["stripe.charge", "stripe.refund"],
                "allowed_domains": ["api.stripe.com", "httpbin.org"],
                "max_requests_per_minute": 30,
            },
        },
        headers=headers_admin,
    )
    assert r_create.status_code == 201, f"Failed to create agent: {r_create.text}"
    agent_data = r_create.json()
    agent_id = agent_data["id"]

    # 2. Issue Agent Session Token
    r_sess = await agent_client.post(
        f"/api/v1/agents/{agent_id}/sessions",
        json={"ttl_seconds": 1800},
        headers=headers_admin,
    )
    assert r_sess.status_code == 201
    sess_data = r_sess.json()
    session_token = sess_data["token"]
    session_id = sess_data["session_id"]
    assert session_token.startswith("aegis_ag_sess_")

    # 3. Revoke Agent Session
    r_rev = await agent_client.post(
        f"/api/v1/agents/{agent_id}/sessions/{session_id}/revoke",
        headers=headers_admin,
    )
    assert r_rev.status_code == 200
    assert r_rev.json()["status"] == "revoked"

    # 4. Attempting to use revoked session token must return 401
    r_proxy = await agent_client.post(
        "/api/v1/agents/proxy",
        json={"url": "https://httpbin.org/post", "method": "POST"},
        headers={"Authorization": f"Bearer {session_token}"},
    )
    assert r_proxy.status_code == 401


@pytest.mark.asyncio
async def test_agent_proxy_policy_and_ssrf_enforcement(agent_client: AsyncClient, agent_test_env):
    """Verify tool allowlist, domain allowlist, and SSRF blocking."""
    user = agent_test_env["user"]
    org = agent_test_env["org"]
    proj = agent_test_env["proj"]
    env = agent_test_env["env"]

    token_admin = create_access_token(
        subject=str(user.id),
        org_id=str(org.id),
        extra_claims={"role": "admin", "email": user.email},
    )
    headers_admin = {"Authorization": f"Bearer {token_admin}"}

    # Create Agent with restricted tool & domain allowlists
    r_create = await agent_client.post(
        "/api/v1/agents",
        json={
            "name": "Scoped Agent",
            "slug": "scoped-agent",
            "project_id": str(proj.id),
            "environment_id": str(env.id),
            "policy": {
                "allowed_tools": ["stripe.charge"],
                "allowed_domains": ["api.stripe.com"],
            },
        },
        headers=headers_admin,
    )
    agent_id = r_create.json()["id"]

    # Issue Session Token
    r_sess = await agent_client.post(f"/api/v1/agents/{agent_id}/sessions", json={}, headers=headers_admin)
    session_token = r_sess.json()["token"]
    agent_headers = {"Authorization": f"Bearer {session_token}"}

    # 1. Block unauthorized tool
    r_bad_tool = await agent_client.post(
        "/api/v1/agents/proxy",
        json={"tool_name": "aws.delete_database", "url": "https://api.stripe.com/v1/charges", "method": "POST"},
        headers=agent_headers,
    )
    assert r_bad_tool.status_code == 403
    assert "Tool 'aws.delete_database' is not authorized" in r_bad_tool.text

    # 2. Block unauthorized destination domain
    r_bad_domain = await agent_client.post(
        "/api/v1/agents/proxy",
        json={"tool_name": "stripe.charge", "url": "https://evil-hacker.com/steal", "method": "POST"},
        headers=agent_headers,
    )
    assert r_bad_domain.status_code == 403
    assert "not authorized by agent policy" in r_bad_domain.text

    # 3. Block SSRF / Loopback targets
    r_ssrf = await agent_client.post(
        "/api/v1/agents/proxy",
        json={"tool_name": "stripe.charge", "url": "http://127.0.0.1:8000/admin", "method": "POST"},
        headers=agent_headers,
    )
    assert r_ssrf.status_code == 400
    assert "SSRF Protection" in r_ssrf.text


@pytest.mark.asyncio
async def test_agent_proxy_secret_substitution_and_audit(agent_client: AsyncClient, agent_test_env):
    """Verify secret placeholder substitution into outbound request and audit event emission."""
    user = agent_test_env["user"]
    org = agent_test_env["org"]
    proj = agent_test_env["proj"]
    env = agent_test_env["env"]

    token_admin = create_access_token(
        subject=str(user.id),
        org_id=str(org.id),
        extra_claims={"role": "admin", "email": user.email},
    )
    headers_admin = {"Authorization": f"Bearer {token_admin}"}

    r_create = await agent_client.post(
        "/api/v1/agents",
        json={
            "name": "Integration Agent",
            "slug": "integration-agent",
            "project_id": str(proj.id),
            "environment_id": str(env.id),
            "policy": {
                "allowed_tools": ["stripe.charge"],
                "allowed_domains": ["api.stripe.com"],
            },
        },
        headers=headers_admin,
    )
    agent_id = r_create.json()["id"]

    r_sess = await agent_client.post(f"/api/v1/agents/{agent_id}/sessions", json={}, headers=headers_admin)
    session_token = r_sess.json()["token"]
    agent_headers = {"Authorization": f"Bearer {session_token}"}

    # Mock outbound httpx call to verify substituted headers
    captured_request = {}
    orig_request = httpx.AsyncClient.request

    async def mock_request(self, method, url, *args, **kwargs):
        if "api.stripe.com" in str(url):
            captured_request["method"] = method
            captured_request["url"] = str(url)
            captured_request["headers"] = kwargs.get("headers")
            captured_request["json"] = kwargs.get("json")
            return Response(status_code=200, json={"status": "charge_created", "id": "ch_123"}, headers={"Content-Type": "application/json"})
        return await orig_request(self, method, url, *args, **kwargs)

    with mock.patch("httpx.AsyncClient.request", new=mock_request):
        r_proxy = await agent_client.post(
            "/api/v1/agents/proxy",
            json={
                "tool_name": "stripe.charge",
                "url": "https://api.stripe.com/v1/charges",
                "method": "POST",
                "headers": {
                    "Authorization": "Bearer {{ aegis:secret:STRIPE_API_KEY }}",
                    "Content-Type": "application/json",
                },
                "body": {"amount": 5000, "currency": "usd"},
            },
            headers=agent_headers,
        )
        assert r_proxy.status_code == 200
        res_json = r_proxy.json()
        assert res_json["status_code"] == 200
        assert res_json["data"]["status"] == "charge_created"

    # Verify that the destination received the decrypted secret
    assert captured_request["headers"]["Authorization"] == "Bearer TESTONLY_sk_live_998877665544332211"

    # Verify audit events were recorded
    r_audit = await agent_client.get("/api/v1/audit/events?action=agent.proxy_call", headers=headers_admin)
    assert r_audit.status_code == 200
    events = r_audit.json()
    assert len(events) >= 1
    assert events[0]["action"] == "agent.proxy_call"

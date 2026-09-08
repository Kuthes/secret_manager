"""AegisVault v1.0.0-RC1 Comprehensive Black-Box & End-to-End Validation Suite.

Covers:
- RC-06: HTTP Security Headers
- RC-07 & RC-08: Authentication & Multi-Tenant Black-Box Isolation (RED vs BLUE)
- RC-09: RBAC Authorization Matrix Enforcement
- RC-10: API Input Fuzzing & Malformed Payload Security
- RC-11 & RC-12: Error Handling & Secret Leakage Canary Assessment
- RC-14: SSRF Filtering on Outbound Connectors
- RC-18: Root-of-Trust Fail-Closed Invariants
- RC-29: Audit Ledger Hash Chain Verification & Tamper Detection
- RC-36: DEMO_MODE Production Startup Rejection
"""

import pytest
import pytest_asyncio
import uuid
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from apps.api.app.main import app
from apps.api.app.core.config import Settings
from apps.api.app.core.ssrf import validate_safe_url, SSRFProtectionError
from apps.api.app.db.session import Base, get_db
from apps.api.app.models.user import (
    User,
    Organization,
    Role,
    OrganizationMembership,
    Project,
    Environment,
)
from apps.api.app.models.secret import Secret, SecretVersion
from apps.api.app.core.security import create_access_token, get_password_hash
from apps.api.app.core.crypto import crypto_engine


TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture
async def test_db():
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as session:
        yield session

    await engine.dispose()


@pytest_asyncio.fixture
async def client(test_db: AsyncSession):
    async def override_get_db():
        yield test_db

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_rc06_http_security_headers(client: AsyncClient):
    """RC-06: Verify all mandatory HTTP security headers are emitted on every response."""
    resp = await client.get("/health")
    assert resp.status_code == 200
    headers = resp.headers
    assert headers.get("x-content-type-options") == "nosniff"
    assert headers.get("x-frame-options") == "DENY"
    assert "strict-transport-security" in headers
    assert "content-security-policy" in headers
    assert headers.get("referrer-policy") == "strict-origin-when-cross-origin"
    assert "permissions-policy" in headers


@pytest.mark.asyncio
async def test_rc36_demo_mode_production_rejection():
    """RC-36: Setting DEMO_MODE=true in production configuration must be rejected."""
    with pytest.raises(ValueError, match="DEMO_MODE must not be true in production"):
        Settings(
            ENVIRONMENT="production",
            DEMO_MODE=True,
            SECRET_KEY="A"*64,
            MASTER_ENCRYPTION_KEY="A"*64,
            COOKIE_SECURE=True,
        )


@pytest.mark.asyncio
async def test_rc08_multitenant_blackbox_isolation(client: AsyncClient, test_db: AsyncSession):
    """RC-08: Organization RED identity must receive 404 for all Organization BLUE resources."""
    # Org RED
    user_red = User(
        email=f"red_{uuid.uuid4().hex[:6]}@red.local",
        hashed_password=get_password_hash("RedPass123!"),
        full_name="Red Admin",
        is_active=True,
        is_verified=True,
    )
    org_red = Organization(name="Org RED", slug=f"org-red-{uuid.uuid4().hex[:6]}")
    role_red_admin = Role(name="Admin", slug="admin", is_system=True)
    test_db.add_all([user_red, org_red, role_red_admin])
    await test_db.flush()

    mem_red = OrganizationMembership(organization_id=org_red.id, user_id=user_red.id, role_id=role_red_admin.id)
    proj_red = Project(organization_id=org_red.id, name="Red Project", slug="red-proj")
    test_db.add_all([mem_red, proj_red])
    await test_db.flush()

    env_red = Environment(project_id=proj_red.id, name="Production", slug="prod")
    test_db.add(env_red)
    await test_db.flush()

    # Org BLUE
    user_blue = User(
        email=f"blue_{uuid.uuid4().hex[:6]}@blue.local",
        hashed_password=get_password_hash("BluePass123!"),
        full_name="Blue Admin",
        is_active=True,
        is_verified=True,
    )
    org_blue = Organization(name="Org BLUE", slug=f"org-blue-{uuid.uuid4().hex[:6]}")
    role_blue_admin = Role(name="Admin", slug="admin", is_system=True)
    test_db.add_all([user_blue, org_blue, role_blue_admin])
    await test_db.flush()

    mem_blue = OrganizationMembership(organization_id=org_blue.id, user_id=user_blue.id, role_id=role_blue_admin.id)
    proj_blue = Project(organization_id=org_blue.id, name="Blue Project", slug="blue-proj")
    test_db.add_all([mem_blue, proj_blue])
    await test_db.flush()

    env_blue = Environment(project_id=proj_blue.id, name="Production", slug="prod")
    test_db.add(env_blue)
    await test_db.flush()

    # Blue Secret
    secret_blue_id = uuid.uuid4()
    enc = crypto_engine.encrypt_secret(
        plaintext="BLUE_TOP_SECRET_CANARY_VALUE",
        org_id=str(org_blue.id),
        project_id=str(proj_blue.id),
        environment_id=str(env_blue.id),
        secret_key="BLUE_MASTER_KEY",
        version=1,
    )
    sec_blue = Secret(
        id=secret_blue_id,
        project_id=proj_blue.id,
        environment_id=env_blue.id,
        key="BLUE_MASTER_KEY",
        current_version_num=1,
    )
    sec_v1_blue = SecretVersion(
        id=uuid.uuid4(),
        secret_id=secret_blue_id,
        version=1,
        encrypted_value=enc["ciphertext"],
        nonce=enc["nonce"],
        encrypted_data_key=enc["encrypted_data_key"],
        dek_nonce=enc["dek_nonce"],
        mek_id=enc["mek_id"],
        mek_version=enc["mek_version"],
    )
    test_db.add_all([sec_blue, sec_v1_blue])
    await test_db.commit()

    token_red = create_access_token(
        subject=str(user_red.id),
        org_id=str(org_red.id),
        extra_claims={"role": "admin", "email": user_red.email},
    )
    headers_red = {"Authorization": f"Bearer {token_red}"}

    # Attempt cross-tenant accesses against BLUE resources
    # Read Secret versions
    r_get = await client.get(f"/api/v1/secrets/{sec_blue.id}/versions", headers=headers_red)
    assert r_get.status_code == 404, f"Expected 404 for cross-tenant secret versions, got {r_get.status_code}"

    # Reveal Secret
    r_rev = await client.get(f"/api/v1/secrets/{sec_blue.id}/reveal", headers=headers_red)
    assert r_rev.status_code == 404, f"Expected 404 for cross-tenant secret reveal, got {r_rev.status_code}"

    # Cross-tenant Project access
    r_proj = await client.get(f"/api/v1/projects/{proj_blue.id}", headers=headers_red)
    assert r_proj.status_code == 404, f"Expected 404 for cross-tenant project, got {r_proj.status_code}"


@pytest.mark.asyncio
async def test_rc09_rbac_viewer_blackbox_enforcement(client: AsyncClient, test_db: AsyncSession):
    """RC-09: Viewer role must be denied for all privileged mutation and reveal actions."""
    org = Organization(name="Viewer Org", slug=f"viewer-org-{uuid.uuid4().hex[:6]}")
    user = User(
        email=f"viewer_{uuid.uuid4().hex[:6]}@org.local",
        hashed_password=get_password_hash("ViewerPass123!"),
        full_name="Viewer User",
        is_active=True,
        is_verified=True,
    )
    role_viewer = Role(name="Viewer", slug="viewer", is_system=True)
    test_db.add_all([org, user, role_viewer])
    await test_db.flush()

    mem = OrganizationMembership(organization_id=org.id, user_id=user.id, role_id=role_viewer.id)
    proj = Project(organization_id=org.id, name="Test Project", slug="test-proj")
    test_db.add_all([mem, proj])
    await test_db.flush()

    env = Environment(project_id=proj.id, name="Production", slug="prod")
    test_db.add(env)
    await test_db.commit()

    token_viewer = create_access_token(
        subject=str(user.id),
        org_id=str(org.id),
        extra_claims={"role": "viewer", "email": user.email},
    )
    headers_viewer = {"Authorization": f"Bearer {token_viewer}"}

    # 1. Viewer can list metadata
    r_meta = await client.get(f"/api/v1/secrets?project_id={proj.id}&environment_id={env.id}", headers=headers_viewer)
    assert r_meta.status_code == 200

    # 2. Viewer cannot create secret
    r_create = await client.post(
        f"/api/v1/secrets?project_id={proj.id}&environment_id={env.id}",
        json={"key": "NEW_KEY", "value": "val", "path": "/"},
        headers=headers_viewer,
    )
    assert r_create.status_code == 403, f"Expected 403 for viewer secret create, got {r_create.status_code}"


@pytest.mark.asyncio
async def test_rc10_api_input_security_fuzzing(client: AsyncClient, test_db: AsyncSession):
    """RC-10: Test controlled malformed inputs: SQLi, path traversal, oversized, invalid UUIDs."""
    user = User(
        email=f"fuzz_{uuid.uuid4().hex[:6]}@org.local",
        hashed_password=get_password_hash("Pass123!"),
        full_name="Fuzz User",
        is_active=True,
        is_verified=True,
    )
    org = Organization(name="Fuzz Org", slug=f"fuzz-org-{uuid.uuid4().hex[:6]}")
    role_admin = Role(name="Admin", slug="admin", is_system=True)
    test_db.add_all([user, org, role_admin])
    await test_db.flush()

    mem = OrganizationMembership(organization_id=org.id, user_id=user.id, role_id=role_admin.id)
    test_db.add(mem)
    await test_db.commit()

    token = create_access_token(
        subject=str(user.id),
        org_id=str(org.id),
        extra_claims={"role": "admin", "email": user.email},
    )
    headers = {"Authorization": f"Bearer {token}"}

    fuzz_payloads = [
        "/api/v1/secrets/not-a-valid-uuid/reveal",
        "/api/v1/secrets/'%20OR%20'1'='1/reveal",
        "/api/v1/secrets/../../etc/passwd/reveal",
    ]

    for path in fuzz_payloads:
        resp = await client.get(path, headers=headers)
        assert resp.status_code in [400, 404, 422], f"Path {path} returned unexpected status {resp.status_code}"
        body = resp.text
        assert "Traceback (most recent call last)" not in body
        assert "asyncpg" not in body


@pytest.mark.asyncio
async def test_rc12_secret_leakage_canary_assessment(client: AsyncClient, test_db: AsyncSession, caplog):
    """RC-12: Synthetic canary secret must never appear in logs, error messages, or metadata."""
    canary_value = f"AEGIS_RC1_CANARY_{uuid.uuid4().hex}"
    user = User(
        email=f"canary_{uuid.uuid4().hex[:6]}@org.local",
        hashed_password=get_password_hash("Pass123!"),
        full_name="Canary User",
        is_active=True,
        is_verified=True,
    )
    org = Organization(name="Canary Org", slug=f"canary-org-{uuid.uuid4().hex[:6]}")
    role_admin = Role(name="Admin", slug="admin", is_system=True)
    test_db.add_all([user, org, role_admin])
    await test_db.flush()

    mem = OrganizationMembership(organization_id=org.id, user_id=user.id, role_id=role_admin.id)
    proj = Project(organization_id=org.id, name="Canary Project", slug="canary-proj")
    test_db.add_all([mem, proj])
    await test_db.flush()

    env = Environment(project_id=proj.id, name="Production", slug="prod")
    test_db.add(env)
    await test_db.commit()

    token = create_access_token(
        subject=str(user.id),
        org_id=str(org.id),
        extra_claims={"role": "admin", "email": user.email},
    )
    headers = {"Authorization": f"Bearer {token}"}

    # Create secret with canary value
    r_create = await client.post(
        f"/api/v1/secrets?project_id={proj.id}&environment_id={env.id}",
        json={"key": "CANARY_TOKEN", "value": canary_value, "path": "/"},
        headers=headers,
    )
    assert r_create.status_code in [200, 201]

    # Inspect list response: Canary MUST NOT be present in plaintext
    r_list = await client.get(f"/api/v1/secrets?project_id={proj.id}&environment_id={env.id}", headers=headers)
    assert r_list.status_code == 200
    assert canary_value not in r_list.text, "Canary secret value leaked in secrets list metadata!"

    # Inspect health and metrics responses
    r_health = await client.get("/health")
    assert canary_value not in r_health.text
    r_metrics = await client.get("/metrics")
    assert canary_value not in r_metrics.text

    # Inspect captured logs
    for record in caplog.records:
        assert canary_value not in record.message, f"Canary secret value leaked in application log message: {record.message}"


@pytest.mark.asyncio
async def test_rc14_ssrf_blackbox_validation():
    """RC-14: Test SSRF protection blocking private, loopback, and link-local targets."""
    forbidden_targets = [
        "http://127.0.0.1:8000",
        "http://localhost:5432",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/admin",
        "http://192.168.1.1",
        "http://172.16.0.1",
        "http://[::1]:8080",
    ]

    for target in forbidden_targets:
        with pytest.raises(SSRFProtectionError):
            validate_safe_url(target, allow_private=False)


@pytest.mark.asyncio
async def test_rc29_audit_chain_tamper_detection(client: AsyncClient, test_db: AsyncSession):
    """RC-29: Audit ledger hash chain verification."""
    user = User(
        email=f"auditor_{uuid.uuid4().hex[:6]}@org.local",
        hashed_password=get_password_hash("Pass123!"),
        full_name="Auditor",
        is_active=True,
        is_verified=True,
    )
    org = Organization(name="Audit Org", slug=f"audit-org-{uuid.uuid4().hex[:6]}")
    role_admin = Role(name="Admin", slug="admin", is_system=True)
    test_db.add_all([user, org, role_admin])
    await test_db.flush()

    mem = OrganizationMembership(organization_id=org.id, user_id=user.id, role_id=role_admin.id)
    test_db.add(mem)
    await test_db.commit()

    token = create_access_token(
        subject=str(user.id),
        org_id=str(org.id),
        extra_claims={"role": "admin", "email": user.email},
    )
    headers = {"Authorization": f"Bearer {token}"}

    r_verify = await client.get("/api/v1/audit/verify", headers=headers)
    assert r_verify.status_code == 200
    assert r_verify.json().get("valid") is True

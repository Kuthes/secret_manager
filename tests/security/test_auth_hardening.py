import pytest
import pytest_asyncio
import hashlib
import uuid
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from apps.api.app.main import app
from apps.api.app.db.session import Base, get_db
from apps.api.app.core.security import create_access_token, get_password_hash
from apps.api.app.models.user import User, Organization, Role, OrganizationMembership, ServiceIdentity
from apps.api.app.services.auth_service import get_totp_token

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture
async def auth_env():
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        org = Organization(name="Auth Corp", slug="auth-corp")
        db.add(org)
        await db.flush()

        role_owner = Role(organization_id=org.id, name="Owner", slug="owner", is_system=True)
        db.add(role_owner)
        await db.flush()

        # Seed machine service identity
        client_id = "svc_machine_app_123456"
        client_secret = "secret_val_live_abc123xyz789"
        prefix = client_id[:8]
        key_hash = hashlib.sha256(client_secret.encode("utf-8")).hexdigest()

        ident = ServiceIdentity(
            organization_id=org.id,
            name="CI/CD Deployment Runner",
            token_prefix=prefix,
            token_hash=key_hash,
            scopes=["secret:read"],
        )
        db.add(ident)
        await db.commit()

    async def override_get_db():
        async with session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield {
            "client": client,
            "org": org,
            "client_id": client_id,
            "client_secret": client_secret,
        }

    app.dependency_overrides.clear()
    await engine.dispose()


@pytest.mark.asyncio
async def test_user_registration_and_login(auth_env):
    client = auth_env["client"]
    reg_resp = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "newuser@authcorp.com",
            "password": "UltraSecurePass2026!",
            "full_name": "New User",
            "org_name": "New User Org",
        },
    )
    assert reg_resp.status_code == 201
    data = reg_resp.json()
    assert "access_token" in data
    assert data["email"] == "newuser@authcorp.com"

    # Login
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "newuser@authcorp.com", "password": "UltraSecurePass2026!"},
    )
    assert login_resp.status_code == 200
    assert "access_token" in login_resp.json()


@pytest.mark.asyncio
async def test_mfa_totp_lifecycle(auth_env):
    client = auth_env["client"]
    # 1. Register user
    reg_resp = await client.post(
        "/api/v1/auth/register",
        json={"email": "mfa_user@authcorp.com", "password": "MfaPass12345!", "full_name": "MFA User"},
    )
    token = reg_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Setup MFA
    setup_resp = await client.post("/api/v1/auth/mfa/setup", headers=headers)
    assert setup_resp.status_code == 200
    mfa_data = setup_resp.json()
    secret = mfa_data["secret"]
    assert "otpauth://totp/AegisVault" in mfa_data["otpauth_uri"]
    assert len(mfa_data["recovery_codes"]) == 5

    # 3. Verify MFA with valid TOTP code
    valid_code = get_totp_token(secret)
    verify_resp = await client.post("/api/v1/auth/mfa/verify", json={"code": valid_code}, headers=headers)
    assert verify_resp.status_code == 200
    assert verify_resp.json()["mfa_enabled"] is True

    # 4. Login without MFA code fails
    login_fail = await client.post(
        "/api/v1/auth/login",
        json={"email": "mfa_user@authcorp.com", "password": "MfaPass12345!"},
    )
    assert login_fail.status_code == 401
    assert "MFA_REQUIRED" in login_fail.json()["detail"]

    # 5. Login with invalid MFA code fails
    login_invalid = await client.post(
        "/api/v1/auth/login",
        json={"email": "mfa_user@authcorp.com", "password": "MfaPass12345!", "mfa_code": "000000"},
    )
    assert login_invalid.status_code == 401

    # 6. Login with valid MFA code succeeds
    fresh_code = get_totp_token(secret)
    login_success = await client.post(
        "/api/v1/auth/login",
        json={"email": "mfa_user@authcorp.com", "password": "MfaPass12345!", "mfa_code": fresh_code},
    )
    assert login_success.status_code == 200
    assert "access_token" in login_success.json()


@pytest.mark.asyncio
async def test_universal_machine_identity_auth(auth_env):
    t = auth_env
    client = t["client"]

    # Valid machine credentials
    resp = await client.post(
        "/api/v1/auth/machine/universal",
        json={"client_id": t["client_id"], "client_secret": t["client_secret"]},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["identity_type"] == "universal_auth"
    assert data["expires_in"] == 3600

    # Invalid machine credentials
    bad_resp = await client.post(
        "/api/v1/auth/machine/universal",
        json={"client_id": t["client_id"], "client_secret": "wrong_secret"},
    )
    assert bad_resp.status_code == 401


@pytest.mark.asyncio
async def test_kubernetes_machine_auth(auth_env):
    t = auth_env
    client = t["client"]

    resp = await client.post(
        "/api/v1/auth/machine/kubernetes",
        json={"jwt": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.valid_k8s_token_sample"},
        headers={"X-Organization-Id": str(t["org"].id)},
    )
    assert resp.status_code == 200
    assert "access_token" in resp.json()
    assert resp.json()["identity_type"] == "kubernetes_auth"

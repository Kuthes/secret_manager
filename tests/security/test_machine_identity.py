import pytest
import pytest_asyncio
import hashlib
import uuid
import jwt
from datetime import datetime, timedelta, timezone
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from apps.api.app.main import app
from apps.api.app.db.session import Base, get_db
from apps.api.app.core.config import settings
from apps.api.app.models.user import User, Organization, Role, ServiceIdentity

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture
async def machine_env():
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        org = Organization(name="Machine Cloud Corp", slug="machine-cloud")
        db.add(org)
        await db.flush()

        role = Role(organization_id=org.id, name="Developer", slug="developer", is_system=True)
        db.add(role)
        await db.flush()

        # Seed Service Identity for Universal Auth
        client_id = "svc_payments_runner_9999"
        client_secret = "secret_machine_key_secure_12345"
        prefix = client_id[:8]
        key_hash = hashlib.sha256(client_secret.encode("utf-8")).hexdigest()

        ident = ServiceIdentity(
            organization_id=org.id,
            name="Payments Runner Service",
            token_prefix=prefix,
            token_hash=key_hash,
            scopes=["secret:read", "secret:list"],
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
            "ident": ident,
            "client_id": client_id,
            "client_secret": client_secret,
        }

    app.dependency_overrides.clear()
    await engine.dispose()


@pytest.mark.asyncio
async def test_universal_machine_auth_lifecycle(machine_env):
    t = machine_env
    client = t["client"]

    # 1. Valid machine credentials
    resp = await client.post(
        "/api/v1/auth/machine/universal",
        json={"client_id": t["client_id"], "client_secret": t["client_secret"]},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["expires_in"] == 3600
    assert data["identity_type"] == "universal_auth"
    assert data["identity_name"] == "Payments Runner Service"

    # 2. Invalid secret fails
    resp_bad = await client.post(
        "/api/v1/auth/machine/universal",
        json={"client_id": t["client_id"], "client_secret": "wrong_secret_payload"},
    )
    assert resp_bad.status_code == 401


@pytest.mark.asyncio
async def test_kubernetes_machine_auth_lifecycle(machine_env):
    t = machine_env
    client = t["client"]

    # 1. Valid K8s ServiceAccount token
    resp = await client.post(
        "/api/v1/auth/machine/kubernetes",
        json={"jwt": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.valid_service_account_token"},
        headers={"X-Organization-Id": str(t["org"].id)},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["identity_type"] == "kubernetes_auth"
    assert data["expires_in"] == 3600

    # 2. Malformed / short token fails
    resp_short = await client.post(
        "/api/v1/auth/machine/kubernetes",
        json={"jwt": "short"},
        headers={"X-Organization-Id": str(t["org"].id)},
    )
    assert resp_short.status_code == 401


@pytest.mark.asyncio
async def test_jwt_oidc_machine_auth_validation_and_rejections(machine_env):
    t = machine_env
    client = t["client"]
    now = datetime.now(timezone.utc)

    # 1. Valid Signed JWT
    valid_payload = {
        "sub": "github-actions-runner-101",
        "iss": "https://token.actions.githubusercontent.com",
        "aud": "https://aegisvault.internal",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=15)).timestamp()),
    }
    valid_jwt = jwt.encode(valid_payload, settings.SECRET_KEY, algorithm="HS256")

    resp = await client.post(
        "/api/v1/auth/machine/jwt",
        json={"token": valid_jwt},
        headers={"X-Organization-Id": str(t["org"].id)},
    )
    assert resp.status_code == 200
    assert resp.json()["identity_type"] == "jwt_oidc_auth"
    assert resp.json()["identity_name"] == "oidc-workload"

    # 2. Expired JWT rejected
    expired_payload = dict(valid_payload)
    expired_payload["exp"] = int((now - timedelta(minutes=10)).timestamp())
    expired_jwt = jwt.encode(expired_payload, settings.SECRET_KEY, algorithm="HS256")

    resp_exp = await client.post(
        "/api/v1/auth/machine/jwt",
        json={"token": expired_jwt},
        headers={"X-Organization-Id": str(t["org"].id)},
    )
    assert resp_exp.status_code == 401

    # 3. Insecure alg=none strictly rejected
    header = {"alg": "none", "typ": "JWT"}
    header_b64 = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
    payload_b64 = "eyJzdWIiOiJoYWNrZXIifQ"
    none_jwt = f"{header_b64}.{payload_b64}."

    resp_none = await client.post(
        "/api/v1/auth/machine/jwt",
        json={"token": none_jwt},
        headers={"X-Organization-Id": str(t["org"].id)},
    )
    assert resp_none.status_code == 401
    assert "Insecure algorithm 'none' is strictly rejected" in resp_none.json()["detail"]


import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from apps.api.app.core.rate_limiter import reset_memory_rate_limits
from apps.api.app.core.security import create_access_token, get_password_hash
from apps.api.app.db.session import Base, get_db
from apps.api.app.main import app
from apps.api.app.models.audit import AuditEvent
from apps.api.app.models.user import (
    Environment,
    Organization,
    OrganizationMembership,
    Project,
    Role,
    User,
)
from apps.api.app.services.secret_service import secret_service

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture
async def reveal_env():
    reset_memory_rate_limits()
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        # Create Org & Owner
        org = Organization(name="SecOps Corp", slug="secops-corp")
        db.add(org)
        await db.flush()

        role = Role(organization_id=org.id, name="Owner", slug="owner", is_system=True)
        db.add(role)
        await db.flush()

        user = User(
            email="secops_admin@secops.com",
            hashed_password=get_password_hash("AdminPass123!"),
            full_name="SecOps Admin",
        )
        db.add(user)
        await db.flush()

        mem = OrganizationMembership(organization_id=org.id, user_id=user.id, role_id=role.id)
        db.add(mem)

        # Create Project & Environment
        proj = Project(organization_id=org.id, name="Backend API", slug="backend-api")
        db.add(proj)
        await db.flush()

        env = Environment(project_id=proj.id, name="Production", slug="prod")
        db.add(env)
        await db.flush()

        # Create Secret
        secret = await secret_service.create_secret(
            db=db,
            project_id=proj.id,
            environment_id=env.id,
            key="DATABASE_PASSWORD",
            value="TESTONLY_super_secret_db_pass_999",
            comment="Primary DB credential",
            actor_id=user.id,
            actor_name=user.full_name,
        )
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
        token = create_access_token(subject=str(user.id), org_id=str(org.id))
        yield {
            "client": client,
            "org": org,
            "user": user,
            "project": proj,
            "environment": env,
            "secret": secret,
            "token": token,
            "session_factory": session_factory,
        }

    app.dependency_overrides.clear()
    await engine.dispose()
    reset_memory_rate_limits()


@pytest.mark.asyncio
async def test_secret_reveal_justification_and_audit(reveal_env):
    t = reveal_env
    client = t["client"]
    token = t["token"]
    secret = t["secret"]
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Reveal secret with justification
    justification_text = "INCIDENT-4091: Urgent database failover investigation"
    resp = await client.get(
        f"/api/v1/secrets/{secret.id}/reveal",
        params={"justification": justification_text},
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["value"] == "TESTONLY_super_secret_db_pass_999"
    assert data["key"] == "DATABASE_PASSWORD"

    # 2. Verify Audit Log recorded the justification and did NOT leak the secret plaintext
    async with t["session_factory"]() as db:
        stmt = select(AuditEvent).where(
            AuditEvent.action == "secret.reveal",
            AuditEvent.resource_id == str(secret.id),
        )
        res = await db.execute(stmt)
        log = res.scalar_one_or_none()
        assert log is not None
        assert log.actor_id == t["user"].id
        assert log.metadata_json is not None
        assert log.metadata_json.get("justification") == justification_text
        # Ensure plaintext secret is NOT in metadata
        assert "TESTONLY_super_secret_db_pass_999" not in str(log.metadata_json)


@pytest.mark.asyncio
async def test_secret_reveal_rate_limiting_enforced(reveal_env):
    t = reveal_env
    client = t["client"]
    token = t["token"]
    secret = t["secret"]
    headers = {"Authorization": f"Bearer {token}"}

    # Perform 30 reveals (allowed limit)
    for _ in range(30):
        resp = await client.get(
            f"/api/v1/secrets/{secret.id}/reveal",
            params={"justification": "Automated pipeline secret read"},
            headers=headers,
        )
        assert resp.status_code == 200

    # 31st reveal must be blocked by rate limiter with 429
    blocked_resp = await client.get(
        f"/api/v1/secrets/{secret.id}/reveal",
        params={"justification": "Exceeded reveal attempt"},
        headers=headers,
    )
    assert blocked_resp.status_code == 429
    assert "Rate limit exceeded" in blocked_resp.json()["detail"]


@pytest.mark.asyncio
async def test_secret_value_by_key_rate_limiting(reveal_env):
    t = reveal_env
    client = t["client"]
    token = t["token"]
    headers = {"Authorization": f"Bearer {token}"}

    params = {
        "project_id": str(t["project"].id),
        "environment_id": str(t["environment"].id),
        "key": "DATABASE_PASSWORD",
        "justification": "Batch query verification",
    }

    # Consume remaining quota up to 30
    for _ in range(30):
        resp = await client.get("/api/v1/secrets/value", params=params, headers=headers)
        assert resp.status_code == 200

    # 31st request should be rate-limited
    resp_blocked = await client.get("/api/v1/secrets/value", params=params, headers=headers)
    assert resp_blocked.status_code == 429

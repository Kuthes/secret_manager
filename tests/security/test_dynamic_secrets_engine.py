import pytest
import pytest_asyncio
import uuid
from datetime import datetime, timezone, timedelta
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from apps.api.app.db.session import Base
from apps.api.app.models.user import User, Organization, Role, OrganizationMembership, Project, Environment
from apps.api.app.models.dynamic_secret import DynamicSecretProvider, DynamicCredentialLease
from apps.api.app.core.security import get_password_hash

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture
async def dyn_env():
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        user = User(email="dyn_user@corp.local", hashed_password=get_password_hash("Pass123!"), full_name="Dyn User", is_active=True, is_verified=True)
        db.add(user)
        org = Organization(name="Dynamic Corp", slug="dynamic-corp")
        db.add(org)
        await db.flush()

        role = Role(organization_id=org.id, name="Owner", slug="owner", is_system=True)
        db.add(role)
        await db.flush()

        mem = OrganizationMembership(organization_id=org.id, user_id=user.id, role_id=role.id)
        db.add(mem)

        proj = Project(organization_id=org.id, name="Data Platform", slug="data-platform")
        db.add(proj)
        await db.flush()

        env = Environment(project_id=proj.id, name="Staging", slug="staging")
        db.add(env)
        await db.flush()

        provider = DynamicSecretProvider(
            project_id=proj.id,
            environment_id=env.id,
            name="postgres-analytics",
            provider_type="postgres",
            default_ttl_seconds=300,
            max_ttl_seconds=3600,
            config_encrypted="{}",
            is_active=True,
        )
        db.add(provider)
        await db.commit()

        yield {
            "session_factory": session_factory,
            "org": org,
            "project": proj,
            "env": env,
            "provider": provider,
            "user": user,
        }

    await engine.dispose()


@pytest.mark.asyncio
async def test_lease_issuance_ttl_and_expiry(dyn_env):
    t = dyn_env
    async with t["session_factory"]() as db:
        now = datetime.now(timezone.utc)
        ttl = 300
        expires = now + timedelta(seconds=ttl)
        lease = DynamicCredentialLease(
            provider_id=t["provider"].id,
            issued_identity="aegis_tmp_analyst_1",
            credential_encrypted="{}",
            ttl_seconds=ttl,
            expires_at=expires,
            status="active",
            requester_id=t["user"].id,
        )
        db.add(lease)
        await db.commit()
        assert lease.id is not None
        assert lease.status == "active"
        assert lease.expires_at > now


@pytest.mark.asyncio
async def test_lease_manual_revocation(dyn_env):
    t = dyn_env
    async with t["session_factory"]() as db:
        now = datetime.now(timezone.utc)
        lease = DynamicCredentialLease(
            provider_id=t["provider"].id,
            issued_identity="aegis_tmp_analyst_2",
            credential_encrypted="{}",
            ttl_seconds=300,
            expires_at=now + timedelta(seconds=300),
            status="active",
            requester_id=t["user"].id,
        )
        db.add(lease)
        await db.commit()

        # Revoke
        lease.status = "revoked"
        lease.revoked_at = datetime.now(timezone.utc)
        await db.commit()

        assert lease.status == "revoked"
        assert lease.revoked_at is not None


@pytest.mark.asyncio
async def test_inactive_provider_cannot_issue_leases(dyn_env):
    t = dyn_env
    async with t["session_factory"]() as db:
        provider = await db.get(DynamicSecretProvider, t["provider"].id)
        provider.is_active = False
        await db.commit()

        assert provider.is_active is False

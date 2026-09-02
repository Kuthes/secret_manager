import pytest
import pytest_asyncio
import uuid
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from apps.api.app.db.session import Base
from apps.api.app.models.user import User, Organization, Role, OrganizationMembership, Project, Environment
from apps.api.app.models.integration import IntegrationConnection, SecretSync, SecretSyncRun
from apps.api.app.core.security import get_password_hash

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture
async def sync_env():
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        user = User(email="sync_admin@corp.local", hashed_password=get_password_hash("Pass123!"), full_name="Sync Admin", is_active=True, is_verified=True)
        db.add(user)
        org = Organization(name="Sync Corp", slug="sync-corp")
        db.add(org)
        await db.flush()

        role = Role(organization_id=org.id, name="Owner", slug="owner", is_system=True)
        db.add(role)
        await db.flush()

        mem = OrganizationMembership(organization_id=org.id, user_id=user.id, role_id=role.id)
        db.add(mem)

        proj = Project(organization_id=org.id, name="Frontend App", slug="frontend-app")
        db.add(proj)
        await db.flush()

        env = Environment(project_id=proj.id, name="Production", slug="production")
        db.add(env)
        await db.flush()

        conn = IntegrationConnection(
            organization_id=org.id,
            name="Vercel Production Deployment",
            provider_type="vercel",
            credentials_encrypted="{\"token\": \"vercel_token_123\"}",
            status="healthy",
        )
        db.add(conn)
        await db.flush()

        sync = SecretSync(
            project_id=proj.id,
            environment_id=env.id,
            connection_id=conn.id,
            target_path="prj_123/production",
            sync_status="active",
        )
        db.add(sync)
        await db.commit()

        yield {
            "session_factory": session_factory,
            "org": org,
            "project": proj,
            "env": env,
            "conn": conn,
            "sync": sync,
        }

    await engine.dispose()


@pytest.mark.asyncio
async def test_secret_sync_creation_and_status(sync_env):
    t = sync_env
    async with t["session_factory"]() as db:
        sync = await db.get(SecretSync, t["sync"].id)
        assert sync.sync_status == "active"
        assert sync.target_path == "prj_123/production"


@pytest.mark.asyncio
async def test_secret_sync_run_history(sync_env):
    t = sync_env
    async with t["session_factory"]() as db:
        run = SecretSyncRun(
            sync_id=t["sync"].id,
            status="success",
            synced_keys_count=12,
            error_message_redacted=None,
        )
        db.add(run)
        await db.commit()

        assert run.id is not None
        assert run.status == "success"
        assert run.synced_keys_count == 12


@pytest.mark.asyncio
async def test_sync_failure_recording(sync_env):
    t = sync_env
    async with t["session_factory"]() as db:
        failed_run = SecretSyncRun(
            sync_id=t["sync"].id,
            status="failed",
            synced_keys_count=0,
            error_message_redacted="Destination API returned 401 Unauthorized: Invalid Vercel token",
        )
        db.add(failed_run)
        await db.commit()

        assert failed_run.status == "failed"
        assert "401" in failed_run.error_message_redacted

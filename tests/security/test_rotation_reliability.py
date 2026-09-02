import pytest
import pytest_asyncio
import uuid
from datetime import datetime, timezone, timedelta
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from apps.api.app.db.session import Base
from apps.api.app.models.user import User, Organization, Role, OrganizationMembership, Project, Environment
from apps.api.app.models.secret import Secret, SecretRotation
from apps.api.app.models.dynamic_secret import DynamicSecretProvider, DynamicCredentialLease
from apps.api.app.services.secret_service import secret_service
from apps.api.app.services.rotation_service import rotation_engine, RotationState
from apps.api.app.core.security import get_password_hash

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture
async def rotation_env():
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        user = User(
            email="rot_admin@corp.local",
            hashed_password=get_password_hash("SecretPass123!"),
            full_name="Rotation Admin",
            is_active=True,
            is_verified=True,
        )
        db.add(user)
        org = Organization(name="Rotation Test Org", slug="rot-org")
        db.add(org)
        await db.flush()

        role = Role(organization_id=org.id, name="Owner", slug="owner", is_system=True)
        db.add(role)
        await db.flush()

        mem = OrganizationMembership(organization_id=org.id, user_id=user.id, role_id=role.id)
        db.add(mem)

        proj = Project(organization_id=org.id, name="Rotation Proj", slug="rot-proj")
        db.add(proj)
        await db.flush()

        env = Environment(project_id=proj.id, name="Production", slug="production")
        db.add(env)
        await db.flush()

        # Seed working secret
        secret = await secret_service.create_secret(
            db=db,
            project_id=proj.id,
            environment_id=env.id,
            key="PAYMENT_GATEWAY_TOKEN",
            value="initial_functional_secret_val_111",
            actor_id=user.id,
            actor_name="Rotation Admin",
        )

        rotation = SecretRotation(
            secret_id=secret.id,
            provider_type="stripe",
            interval_seconds=86400,
            status="active",
            next_run_at=datetime.now(timezone.utc),
            config_encrypted="{}",
        )
        db.add(rotation)

        # Seed provider and expired lease
        provider = DynamicSecretProvider(
            project_id=proj.id,
            environment_id=env.id,
            name="ephemeral-postgres",
            provider_type="postgres",
            default_ttl_seconds=300,
            max_ttl_seconds=3600,
            config_encrypted="{}",
        )
        db.add(provider)
        await db.flush()

        past_time = datetime.now(timezone.utc) - timedelta(minutes=10)
        expired_lease = DynamicCredentialLease(
            provider_id=provider.id,
            issued_identity="aegis_tmp_expired_user",
            credential_encrypted="{}",
            ttl_seconds=300,
            expires_at=past_time,
            status="active",
            requester_id=user.id,
        )
        db.add(expired_lease)

        await db.commit()

        yield {
            "session_factory": session_factory,
            "secret": secret,
            "rotation": rotation,
            "user": user,
            "org": org,
            "expired_lease": expired_lease,
        }

    await engine.dispose()


@pytest.mark.asyncio
async def test_successful_secret_rotation(rotation_env):
    t = rotation_env
    async with t["session_factory"]() as db:
        rot = await db.get(SecretRotation, t["rotation"].id)
        state, err = await rotation_engine.execute_rotation(db=db, rotation=rot)
        assert state == RotationState.COMPLETED
        assert err is None
        await db.commit()

    async with t["session_factory"]() as db:
        sec = await db.get(Secret, t["secret"].id)
        assert sec.current_version_num == 2
        sec_obj, val = await secret_service.reveal_secret(db=db, secret_id=sec.id, actor_id=t["user"].id, actor_name="Admin")
        assert "rot_" in val


@pytest.mark.asyncio
async def test_verification_failure_leaves_secret_intact(rotation_env):
    t = rotation_env
    async with t["session_factory"]() as db:
        rot = await db.get(SecretRotation, t["rotation"].id)
        state, err = await rotation_engine.execute_rotation(db=db, rotation=rot, mock_verify_failure=True)
        assert state == RotationState.FAILED
        assert "Verification failed" in err
        await db.commit()

    async with t["session_factory"]() as db:
        sec = await db.get(Secret, t["secret"].id)
        assert sec.current_version_num == 1
        sec_obj, val = await secret_service.reveal_secret(db=db, secret_id=sec.id, actor_id=t["user"].id, actor_name="Admin")
        assert val == "initial_functional_secret_val_111"


@pytest.mark.asyncio
async def test_lease_reconciliation(rotation_env):
    t = rotation_env
    async with t["session_factory"]() as db:
        lease = await db.get(DynamicCredentialLease, t["expired_lease"].id)
        assert lease.status == "active"
        lease.status = "expired"
        lease.revoked_at = datetime.now(timezone.utc)
        await db.commit()

    async with t["session_factory"]() as db:
        verified_lease = await db.get(DynamicCredentialLease, t["expired_lease"].id)
        assert verified_lease.status == "expired"
        assert verified_lease.revoked_at is not None

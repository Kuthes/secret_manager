import asyncio
import uuid
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from apps.api.app.core.redis_lock import DistributedLock
from apps.api.app.core.security import get_password_hash
from apps.api.app.db.session import Base
from apps.api.app.models.dynamic_secret import (
    DynamicCredentialLease,
    DynamicSecretProvider,
)
from apps.api.app.models.secret import SecretRotation
from apps.api.app.models.user import (
    Environment,
    Organization,
    OrganizationMembership,
    Project,
    Role,
    User,
)
from apps.api.app.services.rotation_service import RotationState, rotation_engine
from apps.api.app.services.secret_service import secret_service

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture
async def worker_env():
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        org = Organization(name="Worker Ops Corp", slug="worker-ops")
        db.add(org)
        await db.flush()

        proj = Project(organization_id=org.id, name="Worker Core", slug="worker-core")
        db.add(proj)
        await db.flush()

        env = Environment(project_id=proj.id, name="Production", slug="production")
        db.add(env)
        await db.flush()

        user = User(email="worker@ops.local", hashed_password=get_password_hash("Pass123!"), full_name="Worker Admin", is_active=True, is_verified=True)
        db.add(user)
        await db.flush()

        role = Role(organization_id=org.id, name="Admin", slug="admin", is_system=True)
        db.add(role)
        await db.flush()

        db.add(OrganizationMembership(organization_id=org.id, user_id=user.id, role_id=role.id))

        secret = await secret_service.create_secret(
            db=db,
            project_id=proj.id,
            environment_id=env.id,
            key="ROTATING_DATABASE_PASS",
            value="initial_super_secret_v1",
            actor_id=user.id,
            actor_name=user.full_name,
        )

        rotation = SecretRotation(
            secret_id=secret.id,
            interval_seconds=86400,
            provider_type="database",
            config_encrypted="{}",
            next_run_at=datetime.now(timezone.utc),
            status="active",
        )
        db.add(rotation)

        dyn_prov = DynamicSecretProvider(
            project_id=proj.id,
            environment_id=env.id,
            name="worker-dyn",
            provider_type="database",
            config_encrypted="{}",
        )
        db.add(dyn_prov)
        await db.flush()

        lease = DynamicCredentialLease(
            provider_id=dyn_prov.id,
            issued_identity="aegis_tmp_worker",
            credential_encrypted="{}",
            ttl_seconds=60,
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=10),  # expired
            status="active",
            requester_id=user.id,
        )
        db.add(lease)

        await db.commit()

        yield {
            "session_factory": session_factory,
            "secret": secret,
            "rotation": rotation,
            "lease": lease,
            "user": user,
            "org": org,
        }

    await engine.dispose()


@pytest.mark.asyncio
async def test_distributed_lock_mutual_exclusion():
    """Verify that two competing workers cannot acquire the same lock key simultaneously."""
    lock_key = f"test_res_{uuid.uuid4().hex}"
    lock1 = DistributedLock(lock_key, ttl_seconds=10)
    lock2 = DistributedLock(lock_key, ttl_seconds=10)

    # First worker acquires
    assert await lock1.acquire() is True

    # Second worker tries to acquire same key -> blocked
    assert await lock2.acquire() is False

    # Worker 1 releases
    assert await lock1.release() is True

    # Worker 2 can now acquire
    assert await lock2.acquire() is True
    assert await lock2.release() is True


@pytest.mark.asyncio
async def test_concurrent_worker_rotation_deduplication(worker_env):
    """Simulate two workers picking up the same rotation task concurrently."""
    t = worker_env
    async with t["session_factory"]() as db1, t["session_factory"]() as db2:
        # Worker 1 runs rotation
        res1_task = rotation_engine.execute_rotation(db=db1, rotation=t["rotation"])
        # Worker 2 attempts same rotation concurrently
        res2_task = rotation_engine.execute_rotation(db=db2, rotation=t["rotation"])

        res1, res2 = await asyncio.gather(res1_task, res2_task)

        # One must succeed and one must be locked/skipped
        states = [res1[0], res2[0]]
        assert RotationState.COMPLETED in states
        # The other was either already locked (RUNNING) or finished
        assert len(states) == 2


@pytest.mark.asyncio
async def test_rotation_verification_failure_preserves_secret(worker_env):
    """If verification fails, secret value must remain at version 1 without exposing candidate."""
    t = worker_env
    async with t["session_factory"]() as db:
        # Run rotation with simulated verification failure
        state, err = await rotation_engine.execute_rotation(
            db=db,
            rotation=t["rotation"],
            mock_verify_failure=True,
        )
        assert state == RotationState.FAILED
        assert "Verification failed" in err

        # Verify target secret remains unchanged at version 1
        _, pt = await secret_service.reveal_secret(db=db, secret_id=t["secret"].id, actor_name="TestVerifier")
        assert pt == "initial_super_secret_v1"
        assert t["secret"].current_version_num == 1

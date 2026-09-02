import pytest
import pytest_asyncio
import uuid
from datetime import datetime, timezone, timedelta
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from apps.api.app.db.session import Base
from apps.api.app.models.user import User, Organization, Role, OrganizationMembership, Project, Environment
from apps.api.app.models.secret import Secret
from apps.api.app.services.secret_service import secret_service
from apps.api.app.core.security import get_password_hash, verify_password, create_access_token, decode_access_token

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture
async def comp_env():
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        user = User(email="admin@comp.local", hashed_password=get_password_hash("Pass12345!"), full_name="Matrix Admin", is_active=True, is_verified=True)
        db.add(user)
        org = Organization(name="Matrix Corp", slug="matrix-corp")
        db.add(org)
        await db.flush()

        role = Role(organization_id=org.id, name="Owner", slug="owner", is_system=True)
        db.add(role)
        await db.flush()

        mem = OrganizationMembership(organization_id=org.id, user_id=user.id, role_id=role.id)
        db.add(mem)

        proj = Project(organization_id=org.id, name="Matrix App", slug="matrix-app")
        db.add(proj)
        await db.flush()

        env = Environment(project_id=proj.id, name="Production", slug="production")
        db.add(env)
        await db.flush()

        secret = await secret_service.create_secret(
            db=db,
            project_id=proj.id,
            environment_id=env.id,
            key="API_SECRET_KEY",
            value="initial_value_v1",
            actor_id=user.id,
            actor_name="Matrix Admin",
        )
        await db.commit()

        yield {
            "session_factory": session_factory,
            "org": org,
            "project": proj,
            "env": env,
            "secret": secret,
            "user": user,
        }

    await engine.dispose()


def test_password_hash_verification():
    pw = "SuperSecurePassword999!"
    hashed = get_password_hash(pw)
    assert verify_password(pw, hashed) is True
    assert verify_password("WrongPassword123!", hashed) is False
    assert verify_password("", hashed) is False


def test_jwt_token_validity_and_tampering():
    sub = str(uuid.uuid4())
    org_id = str(uuid.uuid4())
    token = create_access_token(subject=sub, org_id=org_id)
    payload = decode_access_token(token)
    assert payload["sub"] == sub
    assert payload["org_id"] == org_id

    # Tampered token (invalid signature) returns None
    tampered = token[:-4] + "AAAA"
    assert decode_access_token(tampered) is None


@pytest.mark.asyncio
async def test_secret_versioning_and_rollback_sequence(comp_env):
    t = comp_env
    async with t["session_factory"]() as db:
        sec = await db.get(Secret, t["secret"].id)
        assert sec.current_version_num == 1

        # Version 2
        await secret_service.update_secret(db=db, secret_id=sec.id, value="updated_value_v2", change_message="Bump v2")
        await db.commit()

    async with t["session_factory"]() as db:
        sec = await db.get(Secret, t["secret"].id)
        assert sec.current_version_num == 2

        # Version 3
        await secret_service.update_secret(db=db, secret_id=sec.id, value="updated_value_v3", change_message="Bump v3")
        await db.commit()

    async with t["session_factory"]() as db:
        sec = await db.get(Secret, t["secret"].id)
        assert sec.current_version_num == 3

        # Rollback to Version 1 -> creates Version 4 with value from Version 1
        rolled = await secret_service.rollback_secret(db=db, secret_id=sec.id, target_version_num=1, reason="Rollback v1")
        assert rolled.current_version_num == 4
        await db.commit()

    async with t["session_factory"]() as db:
        _, val = await secret_service.reveal_secret(db=db, secret_id=sec.id, actor_id=t["user"].id, actor_name="Admin")
        assert val == "initial_value_v1"


@pytest.mark.asyncio
async def test_soft_deletion_and_isolation(comp_env):
    t = comp_env
    async with t["session_factory"]() as db:
        sec = await db.get(Secret, t["secret"].id)
        sec.is_deleted = True
        sec.deleted_at = datetime.now(timezone.utc)
        await db.commit()

    # Attempting reveal on soft-deleted secret must return 404
    async with t["session_factory"]() as db:
        with pytest.raises(HTTPException) as exc_info:
            await secret_service.reveal_secret(db=db, secret_id=t["secret"].id, actor_id=t["user"].id, actor_name="Admin")
        assert exc_info.value.status_code == 404

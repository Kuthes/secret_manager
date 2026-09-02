import pytest
import pytest_asyncio
import uuid
from datetime import datetime, timezone
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from apps.api.app.db.session import Base
from apps.api.app.models.user import User, Organization, Role, OrganizationMembership, Project
from apps.api.app.models.pam import AccessResource, AccessRequest
from apps.api.app.services.pam_service import pam_service
from apps.api.app.core.security import get_password_hash

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture
async def pam_env():
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        org = Organization(name="PAM Corp", slug="pam-corp")
        db.add(org)
        await db.flush()

        proj = Project(organization_id=org.id, name="Infra", slug="infra")
        db.add(proj)
        await db.flush()

        role = Role(organization_id=org.id, name="Admin", slug="admin", is_system=True)
        db.add(role)
        await db.flush()

        user1 = User(email="requester@pam.local", hashed_password=get_password_hash("Pass123!"), full_name="Requester", is_active=True, is_verified=True)
        user2 = User(email="approver@pam.local", hashed_password=get_password_hash("Pass123!"), full_name="Approver", is_active=True, is_verified=True)
        db.add_all([user1, user2])
        await db.flush()

        db.add_all([
            OrganizationMembership(organization_id=org.id, user_id=user1.id, role_id=role.id),
            OrganizationMembership(organization_id=org.id, user_id=user2.id, role_id=role.id),
        ])

        resource = AccessResource(
            organization_id=org.id,
            project_id=proj.id,
            name="Prod Kubernetes Cluster",
            resource_type="k8s",
            resource_identifier="k8s.prod.corp.local",
            max_duration_seconds=3600,
        )
        db.add(resource)
        await db.commit()

        yield {
            "session_factory": session_factory,
            "org": org,
            "resource": resource,
            "requester": user1,
            "approver": user2,
        }

    await engine.dispose()


@pytest.mark.asyncio
async def test_self_approval_prevented(pam_env):
    t = pam_env
    async with t["session_factory"]() as db:
        req = await pam_service.create_request(
            db=db,
            resource_id=t["resource"].id,
            requester_id=t["requester"].id,
            requester_name=t["requester"].full_name,
            justification="Self-approval test",
            duration_seconds=1800,
        )
        await db.commit()

        # Requester tries to review and approve own request
        with pytest.raises(HTTPException) as exc_info:
            await pam_service.review_request(
                db=db,
                request_id=req.id,
                approver_id=t["requester"].id,
                approver_name=t["requester"].full_name,
                decision="approved",
            )
        assert exc_info.value.status_code == 403
        assert "Self-approval forbidden" in exc_info.value.detail


@pytest.mark.asyncio
async def test_successful_approval_flow_and_duration_clamping(pam_env):
    t = pam_env
    async with t["session_factory"]() as db:
        # Request 100,000s, resource max is 3600s
        req = await pam_service.create_request(
            db=db,
            resource_id=t["resource"].id,
            requester_id=t["requester"].id,
            requester_name=t["requester"].full_name,
            justification="Investigating outage",
            duration_seconds=100000,
        )
        # Clamped to max_duration_seconds (3600)
        assert req.duration_seconds == 3600

        # Separate approver reviews request
        approved_req = await pam_service.review_request(
            db=db,
            request_id=req.id,
            approver_id=t["approver"].id,
            approver_name=t["approver"].full_name,
            decision="approved",
            comment="Approved for emergency fix",
        )
        assert approved_req.status == "approved"
        assert approved_req.expires_at is not None


@pytest.mark.asyncio
async def test_early_revocation(pam_env):
    t = pam_env
    async with t["session_factory"]() as db:
        req = await pam_service.create_request(
            db=db,
            resource_id=t["resource"].id,
            requester_id=t["requester"].id,
            requester_name=t["requester"].full_name,
            justification="Task finished early",
            duration_seconds=1800,
        )
        revoked = await pam_service.revoke_request(
            db=db,
            request_id=req.id,
            actor_id=t["approver"].id,
            actor_name=t["approver"].full_name,
            reason="Work completed ahead of schedule",
        )
        assert revoked.status == "revoked"
        assert revoked.revoked_at is not None

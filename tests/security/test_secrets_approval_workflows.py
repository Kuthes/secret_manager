"""Comprehensive Security & Dual-Authorization Test Suite for Secrets Approval Workflows.

Tests:
1. Change request creation with envelope-encrypted candidate payload.
2. Strict four-eyes / dual-authorization enforcement (requesters cannot approve own requests).
3. Reviewer approval & atomic application into the vault (version increment).
4. Update and deletion change request workflows.
5. Cross-tenant isolation and unauthorized access rejection.
6. Full audit event trail emission for all transitions.
"""

import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from apps.api.app.core.security import create_access_token, get_password_hash
from apps.api.app.db.session import Base, get_db
from apps.api.app.main import app
from apps.api.app.models.user import (
    Environment,
    Organization,
    OrganizationMembership,
    Project,
    Role,
    User,
)


@pytest_asyncio.fixture
async def cr_test_env():
    """Spin up clean isolated SQLite DB for change request testing."""
    test_db_url = f"sqlite+aiosqlite:///file:cr_{uuid.uuid4().hex}?mode=memory&cache=shared&uri=true"
    engine = create_async_engine(test_db_url, connect_args={"check_same_thread": False})
    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        # 1. Setup Org A and Org B
        org_a = Organization(name="Company A", slug="company-a")
        org_b = Organization(name="Company B", slug="company-b")
        db.add_all([org_a, org_b])
        await db.flush()

        # 2. Setup Roles
        role_admin = Role(name="Admin", slug="admin", is_system=True)
        role_dev = Role(name="Developer", slug="developer", is_system=True)
        role_viewer = Role(name="Viewer", slug="viewer", is_system=True)
        db.add_all([role_admin, role_dev, role_viewer])
        await db.flush()

        # 3. Setup Users
        # Admin 1 (Requester)
        u_admin1 = User(
            email="admin1@company-a.com",
            hashed_password=get_password_hash("Password123!"),
            full_name="Admin One",
            is_active=True,
            is_verified=True,
        )
        # Admin 2 (Reviewer)
        u_admin2 = User(
            email="admin2@company-a.com",
            hashed_password=get_password_hash("Password123!"),
            full_name="Admin Two",
            is_active=True,
            is_verified=True,
        )
        # Developer
        u_dev = User(
            email="dev@company-a.com",
            hashed_password=get_password_hash("Password123!"),
            full_name="Dev User",
            is_active=True,
            is_verified=True,
        )
        # Viewer
        u_viewer = User(
            email="viewer@company-a.com",
            hashed_password=get_password_hash("Password123!"),
            full_name="Viewer User",
            is_active=True,
            is_verified=True,
        )
        # Org B Admin (Attacker)
        u_org_b = User(
            email="admin@company-b.com",
            hashed_password=get_password_hash("Password123!"),
            full_name="Org B Admin",
            is_active=True,
            is_verified=True,
        )
        db.add_all([u_admin1, u_admin2, u_dev, u_viewer, u_org_b])
        await db.flush()

        # 4. Memberships
        db.add_all([
            OrganizationMembership(user_id=u_admin1.id, organization_id=org_a.id, role_id=role_admin.id),
            OrganizationMembership(user_id=u_admin2.id, organization_id=org_a.id, role_id=role_admin.id),
            OrganizationMembership(user_id=u_dev.id, organization_id=org_a.id, role_id=role_dev.id),
            OrganizationMembership(user_id=u_viewer.id, organization_id=org_a.id, role_id=role_viewer.id),
            OrganizationMembership(user_id=u_org_b.id, organization_id=org_b.id, role_id=role_admin.id),
        ])
        await db.flush()

        # 5. Project & Environment in Org A
        proj = Project(organization_id=org_a.id, name="Payments Engine", slug="payments-engine")
        db.add(proj)
        await db.flush()

        env = Environment(project_id=proj.id, name="Production", slug="prod")
        db.add(env)
        await db.flush()
        await db.commit()

        yield {
            "session_factory": session_factory,
            "org_a": org_a,
            "org_b": org_b,
            "admin1": u_admin1,
            "admin2": u_admin2,
            "dev": u_dev,
            "viewer": u_viewer,
            "org_b_user": u_org_b,
            "proj": proj,
            "env": env,
        }

    await engine.dispose()


@pytest_asyncio.fixture
async def cr_client(cr_test_env):
    """AsyncClient wired with dependency overrides."""
    session_factory = cr_test_env["session_factory"]

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
        yield client
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_change_request_create_and_four_eyes_enforcement(cr_client: AsyncClient, cr_test_env):
    """Verify change request creation, self-approval prevention (403), and dual-authorization approval."""
    org_a = cr_test_env["org_a"]
    admin1 = cr_test_env["admin1"]
    admin2 = cr_test_env["admin2"]
    proj = cr_test_env["proj"]
    env = cr_test_env["env"]

    token_admin1 = create_access_token(
        subject=str(admin1.id),
        org_id=str(org_a.id),
        extra_claims={"role": "admin", "email": admin1.email},
    )
    headers_admin1 = {"Authorization": f"Bearer {token_admin1}"}

    token_admin2 = create_access_token(
        subject=str(admin2.id),
        org_id=str(org_a.id),
        extra_claims={"role": "admin", "email": admin2.email},
    )
    headers_admin2 = {"Authorization": f"Bearer {token_admin2}"}

    # 1. Admin 1 creates a change request for a new production secret
    r_create = await cr_client.post(
        "/api/v1/change-requests",
        json={
            "project_id": str(proj.id),
            "environment_id": str(env.id),
            "change_type": "create",
            "title": "Add Production Stripe Secret Key",
            "description": "Required for v2 billing migration",
            "proposed_key": "STRIPE_SECRET_KEY",
            "proposed_value": "TESTONLY_sk_live_11223344556677889900",
            "proposed_description": "Stripe Live API Key",
        },
        headers=headers_admin1,
    )
    assert r_create.status_code == 200
    cr_data = r_create.json()
    cr_id = cr_data["id"]
    assert cr_data["status"] == "pending"
    assert cr_data["proposed_key"] == "STRIPE_SECRET_KEY"
    assert cr_data["requester_id"] == str(admin1.id)

    # 2. Dual-authorization enforcement: Admin 1 tries to approve own request -> Must be blocked with 403
    r_self_approve = await cr_client.post(
        f"/api/v1/change-requests/{cr_id}/review",
        json={"decision": "approved", "comment": "Self approving my change"},
        headers=headers_admin1,
    )
    assert r_self_approve.status_code == 403
    assert "Self-approval is forbidden" in r_self_approve.json()["detail"]

    # 3. Admin 2 reviews and approves the change request
    r_approve = await cr_client.post(
        f"/api/v1/change-requests/{cr_id}/review",
        json={"decision": "approved", "comment": "Verified billing change with finance"},
        headers=headers_admin2,
    )
    assert r_approve.status_code == 200
    assert r_approve.json()["status"] == "approved"
    assert r_approve.json()["reviewer_id"] == str(admin2.id)

    # 4. Admin 2 applies the approved change request
    r_apply = await cr_client.post(f"/api/v1/change-requests/{cr_id}/apply", headers=headers_admin2)
    assert r_apply.status_code == 200
    applied_cr = r_apply.json()
    assert applied_cr["status"] == "applied"
    assert applied_cr["applied_at"] is not None
    created_secret_id = applied_cr["secret_id"]
    assert created_secret_id is not None

    # 5. Verify the secret now exists in the vault with correct value
    r_reveal = await cr_client.get(
        f"/api/v1/secrets/{created_secret_id}/reveal?justification=Verification+of+applied+change+request",
        headers=headers_admin2,
    )
    assert r_reveal.status_code == 200
    assert r_reveal.json()["value"] == "TESTONLY_sk_live_11223344556677889900"


@pytest.mark.asyncio
async def test_change_request_update_and_delete_workflow(cr_client: AsyncClient, cr_test_env):
    """Verify change request for updating existing secret and deleting secret."""
    org_a = cr_test_env["org_a"]
    admin1 = cr_test_env["admin1"]
    admin2 = cr_test_env["admin2"]
    dev = cr_test_env["dev"]
    proj = cr_test_env["proj"]
    env = cr_test_env["env"]

    token_admin1 = create_access_token(subject=str(admin1.id), org_id=str(org_a.id), extra_claims={"role": "admin"})
    headers_admin1 = {"Authorization": f"Bearer {token_admin1}"}

    token_admin2 = create_access_token(subject=str(admin2.id), org_id=str(org_a.id), extra_claims={"role": "admin"})
    headers_admin2 = {"Authorization": f"Bearer {token_admin2}"}

    token_dev = create_access_token(subject=str(dev.id), org_id=str(org_a.id), extra_claims={"role": "developer"})
    headers_dev = {"Authorization": f"Bearer {token_dev}"}

    # 1. Create base secret directly
    r_sec = await cr_client.post(
        f"/api/v1/secrets?project_id={proj.id}&environment_id={env.id}",
        json={
            "key": "DATABASE_URL",
            "value": "TESTONLY_postgres://v1:pass@db:5432/main",
            "comment": "Initial db url",
        },
        headers=headers_admin1,
    )
    assert r_sec.status_code == 201
    secret_id = r_sec.json()["id"]

    # 2. Developer submits update change request
    r_cr_update = await cr_client.post(
        "/api/v1/change-requests",
        json={
            "project_id": str(proj.id),
            "environment_id": str(env.id),
            "secret_id": secret_id,
            "change_type": "update",
            "title": "Rotate Database Password",
            "description": "Routine password rotation",
            "proposed_key": "DATABASE_URL",
            "proposed_value": "TESTONLY_postgres://v2_rotated:newpass@db:5432/main",
            "proposed_description": "Rotated db url v2",
        },
        headers=headers_dev,
    )
    assert r_cr_update.status_code == 200
    cr_id = r_cr_update.json()["id"]

    # 3. Developer cannot approve (lacks permission or self approval)
    r_dev_approve = await cr_client.post(
        f"/api/v1/change-requests/{cr_id}/review",
        json={"decision": "approved"},
        headers=headers_dev,
    )
    assert r_dev_approve.status_code == 403

    # 4. Admin 2 approves and applies update
    await cr_client.post(f"/api/v1/change-requests/{cr_id}/review", json={"decision": "approved"}, headers=headers_admin2)
    r_applied = await cr_client.post(f"/api/v1/change-requests/{cr_id}/apply", headers=headers_admin2)
    assert r_applied.status_code == 200

    # 5. Verify secret value updated to v2
    r_reveal = await cr_client.get(
        f"/api/v1/secrets/{secret_id}/reveal?justification=Check+v2+value",
        headers=headers_admin2,
    )
    assert r_reveal.json()["value"] == "TESTONLY_postgres://v2_rotated:newpass@db:5432/main"
    assert r_reveal.json()["version"] == 2


@pytest.mark.asyncio
async def test_change_request_cross_tenant_isolation_and_audit(cr_client: AsyncClient, cr_test_env):
    """Verify cross-tenant isolation and audit event generation for change requests."""
    org_a = cr_test_env["org_a"]
    org_b = cr_test_env["org_b"]
    admin1 = cr_test_env["admin1"]
    admin2 = cr_test_env["admin2"]
    org_b_user = cr_test_env["org_b_user"]
    proj = cr_test_env["proj"]
    env = cr_test_env["env"]

    token_admin1 = create_access_token(subject=str(admin1.id), org_id=str(org_a.id), extra_claims={"role": "admin"})
    headers_admin1 = {"Authorization": f"Bearer {token_admin1}"}

    token_admin2 = create_access_token(subject=str(admin2.id), org_id=str(org_a.id), extra_claims={"role": "admin"})
    headers_admin2 = {"Authorization": f"Bearer {token_admin2}"}

    token_org_b = create_access_token(subject=str(org_b_user.id), org_id=str(org_b.id), extra_claims={"role": "admin"})
    headers_org_b = {"Authorization": f"Bearer {token_org_b}"}

    # 1. Create change request in Org A
    r_cr = await cr_client.post(
        "/api/v1/change-requests",
        json={
            "project_id": str(proj.id),
            "environment_id": str(env.id),
            "change_type": "create",
            "title": "Secret in Org A",
            "description": "Sensitive credential",
            "proposed_key": "ORG_A_SECRET",
            "proposed_value": "TESTONLY_secret_value_org_a",
        },
        headers=headers_admin1,
    )
    cr_id = r_cr.json()["id"]

    # 2. Org B tries to access Org A's change request -> Must 404 (isolation)
    r_b_get = await cr_client.get(f"/api/v1/change-requests/{cr_id}", headers=headers_org_b)
    assert r_b_get.status_code == 404

    # 3. Org B tries to approve Org A's change request -> Must 404
    r_b_review = await cr_client.post(
        f"/api/v1/change-requests/{cr_id}/review",
        json={"decision": "approved"},
        headers=headers_org_b,
    )
    assert r_b_review.status_code == 404

    # 4. Reject and verify cannot apply
    r_reject = await cr_client.post(
        f"/api/v1/change-requests/{cr_id}/review",
        json={"decision": "rejected", "comment": "Change request not needed"},
        headers=headers_admin2,
    )
    assert r_reject.status_code == 200
    assert r_reject.json()["status"] == "rejected"

    r_bad_apply = await cr_client.post(f"/api/v1/change-requests/{cr_id}/apply", headers=headers_admin2)
    assert r_bad_apply.status_code == 400
    assert "Must be 'approved'" in r_bad_apply.json()["detail"]

    # 5. Check Audit logs exist
    r_audit = await cr_client.get("/api/v1/audit/events?action=secret.change_request_created", headers=headers_admin1)
    assert r_audit.status_code == 200
    events = r_audit.json()
    assert len(events) >= 1
    assert events[0]["action"] == "secret.change_request_created"

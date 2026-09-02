import pytest
import pytest_asyncio
import uuid
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from apps.api.app.main import app
from apps.api.app.db.session import Base, get_db
from apps.api.app.core.security import create_access_token, get_password_hash
from apps.api.app.models.user import User, Organization, Role, Permission, OrganizationMembership, Project, Environment
from apps.api.app.models.pam import AccessResource, AccessRequest
from apps.api.app.services.secret_service import secret_service
from apps.api.app.services.pki_service import pki_service
from apps.api.app.services.kms_service import kms_service

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture
async def rbac_env():
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        org = Organization(name="RBAC Matrix Corp", slug="rbac-corp")
        db.add(org)
        await db.flush()

        proj = Project(organization_id=org.id, name="Core Platform", slug="core-platform")
        db.add(proj)
        await db.flush()

        env = Environment(project_id=proj.id, name="Production", slug="production")
        db.add(env)
        await db.flush()

        # Roles
        role_owner = Role(organization_id=org.id, name="Owner", slug="owner", is_system=True)
        role_admin = Role(organization_id=org.id, name="Admin", slug="admin", is_system=True)
        role_dev = Role(organization_id=org.id, name="Developer", slug="developer", is_system=True)
        role_viewer = Role(organization_id=org.id, name="Viewer", slug="viewer", is_system=True)
        role_custom = Role(organization_id=org.id, name="Auditor Only", slug="auditor_custom", is_system=False)
        db.add_all([role_owner, role_admin, role_dev, role_viewer, role_custom])
        await db.flush()

        # Custom role permissions: only audit:read and audit:export
        p1 = Permission(role_id=role_custom.id, action="audit:read", resource_scope="*")
        p2 = Permission(role_id=role_custom.id, action="audit:export", resource_scope="*")
        db.add_all([p1, p2])
        await db.flush()

        # Users
        users = {}
        tokens = {}
        for role_obj in [role_owner, role_admin, role_dev, role_viewer, role_custom]:
            u = User(
                email=f"{role_obj.slug}@rbac.local",
                hashed_password=get_password_hash("SecretPass123!"),
                full_name=f"{role_obj.name} User",
                is_active=True,
                is_verified=True,
            )
            db.add(u)
            await db.flush()

            mem = OrganizationMembership(organization_id=org.id, user_id=u.id, role_id=role_obj.id)
            db.add(mem)
            users[role_obj.slug] = u
            tokens[role_obj.slug] = create_access_token(subject=str(u.id), org_id=str(org.id))

        # Seed test resources
        secret = await secret_service.create_secret(
            db=db,
            project_id=proj.id,
            environment_id=env.id,
            key="DATABASE_URL",
            value="postgresql://user:pass@db:5432/app",
            actor_id=users["owner"].id,
            actor_name="Owner User",
        )

        ca = await pki_service.create_ca(
            db=db,
            organization_id=org.id,
            name="RBAC Root CA",
            common_name="RBAC Root Authority",
            actor_id=users["owner"].id,
            actor_name="Owner User",
        )

        cert, _ = await pki_service.issue_certificate(
            db=db,
            ca_id=ca.id,
            common_name="api.rbac.local",
            san_dns_names=["api.rbac.local"],
            actor_id=users["owner"].id,
            actor_name="Owner User",
        )

        key = await kms_service.create_key(
            db=db,
            organization_id=org.id,
            project_id=proj.id,
            name="rbac-key",
            algorithm="AES-256-GCM",
            key_usage="ENCRYPT_DECRYPT",
            actor_id=users["owner"].id,
            actor_name="Owner User",
        )

        pam_res = AccessResource(
            organization_id=org.id,
            project_id=proj.id,
            name="Prod SSH Gateway",
            resource_type="ssh",
            resource_identifier="bastion.rbac.local",
        )
        db.add(pam_res)
        await db.flush()

        pam_req = AccessRequest(
            resource_id=pam_res.id,
            requester_id=users["developer"].id,
            justification="Debugging memory leak",
            duration_seconds=1800,
            status="pending",
        )
        db.add(pam_req)

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
            "org": org, "proj": proj, "env": env,
            "secret": secret, "ca": ca, "cert": cert, "key": key,
            "pam_res": pam_res, "pam_req": pam_req,
            "users": users, "tokens": tokens,
        }

    app.dependency_overrides.clear()
    await engine.dispose()


@pytest.mark.asyncio
async def test_owner_and_admin_full_access(rbac_env):
    t = rbac_env
    client = t["client"]

    for role_name in ["owner", "admin"]:
        token = t["tokens"][role_name]
        headers = {"Authorization": f"Bearer {token}", "X-Organization-Id": str(t["org"].id)}

        # Can list secrets
        resp = await client.get(f"/api/v1/secrets?project_id={t['proj'].id}&environment_id={t['env'].id}", headers=headers)
        assert resp.status_code == 200

        # Can reveal secret
        resp = await client.get(f"/api/v1/secrets/{t['secret'].id}/reveal", headers=headers)
        assert resp.status_code == 200

        # Can create secret
        resp = await client.post(
            f"/api/v1/secrets?project_id={t['proj'].id}&environment_id={t['env'].id}",
            json={"key": f"{role_name.upper()}_KEY", "value": "val"},
            headers=headers,
        )
        assert resp.status_code == 201


@pytest.mark.asyncio
async def test_developer_permissions_and_restrictions(rbac_env):
    t = rbac_env
    client = t["client"]
    headers = {"Authorization": f"Bearer {t['tokens']['developer']}", "X-Organization-Id": str(t["org"].id)}

    # Developer CAN list secrets
    resp = await client.get(f"/api/v1/secrets?project_id={t['proj'].id}&environment_id={t['env'].id}", headers=headers)
    assert resp.status_code == 200

    # Developer CAN reveal secret
    resp = await client.get(f"/api/v1/secrets/{t['secret'].id}/reveal", headers=headers)
    assert resp.status_code == 200

    # Developer CAN create secret
    resp = await client.post(
        f"/api/v1/secrets?project_id={t['proj'].id}&environment_id={t['env'].id}",
        json={"key": "DEV_KEY_NEW", "value": "dev_val"},
        headers=headers,
    )
    assert resp.status_code == 201

    # Developer CANNOT delete secret (Forbidden)
    resp = await client.delete(f"/api/v1/secrets/{t['secret'].id}", headers=headers)
    assert resp.status_code == 403

    # Developer CANNOT create Root CA (Forbidden)
    resp = await client.post("/api/v1/pki/ca", json={"name": "Dev CA", "common_name": "Dev Root"}, headers=headers)
    assert resp.status_code == 403

    # Developer CANNOT approve PAM requests (Forbidden)
    resp = await client.post(f"/api/v1/access/requests/{t['pam_req'].id}/review", json={"decision": "approved"}, headers=headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_viewer_restricted_read_only(rbac_env):
    t = rbac_env
    client = t["client"]
    headers = {"Authorization": f"Bearer {t['tokens']['viewer']}", "X-Organization-Id": str(t["org"].id)}

    # Viewer CAN list secret metadata
    resp = await client.get(f"/api/v1/secrets?project_id={t['proj'].id}&environment_id={t['env'].id}", headers=headers)
    assert resp.status_code == 200

    # Viewer CANNOT reveal plaintext secret
    resp = await client.get(f"/api/v1/secrets/{t['secret'].id}/reveal", headers=headers)
    assert resp.status_code == 403

    # Viewer CANNOT create secret
    resp = await client.post(
        f"/api/v1/secrets?project_id={t['proj'].id}&environment_id={t['env'].id}",
        json={"key": "VIEWER_KEY", "value": "val"},
        headers=headers,
    )
    assert resp.status_code == 403

    # Viewer CANNOT encrypt KMS
    resp = await client.post(f"/api/v1/kms/keys/{t['key'].id}/encrypt", json={"plaintext": "test"}, headers=headers)
    assert resp.status_code == 403

    # Viewer CANNOT issue cert
    resp = await client.post(
        "/api/v1/pki/issue",
        json={"ca_id": str(t["ca"].id), "common_name": "test.local", "san_dns_names": []},
        headers=headers,
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_custom_role_explicit_grants(rbac_env):
    t = rbac_env
    client = t["client"]
    headers = {"Authorization": f"Bearer {t['tokens']['auditor_custom']}", "X-Organization-Id": str(t["org"].id)}

    # Custom Auditor role CAN read audit events
    resp = await client.get("/api/v1/audit/events", headers=headers)
    assert resp.status_code == 200

    # Custom Auditor role CAN verify audit chain
    resp = await client.post("/api/v1/audit/verify", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["valid"] is True

    # Custom Auditor role CAN export audit events
    resp = await client.get("/api/v1/audit/export?format=json", headers=headers)
    assert resp.status_code == 200

    # Custom Auditor role CANNOT reveal secrets
    resp = await client.get(f"/api/v1/secrets/{t['secret'].id}/reveal", headers=headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_pam_self_approval_prevented(rbac_env):
    t = rbac_env
    client = t["client"]
    
    # Dev requester tries to review own request (even if we temporarily simulate admin token)
    # 1. Admin creates their own PAM request
    admin_headers = {"Authorization": f"Bearer {t['tokens']['admin']}", "X-Organization-Id": str(t["org"].id)}
    req_resp = await client.post(
        "/api/v1/access/requests",
        json={"resource_id": str(t["pam_res"].id), "justification": "Admin need", "duration_seconds": 3600},
        headers=admin_headers,
    )
    assert req_resp.status_code == 201
    admin_req_id = req_resp.json()["id"]

    # 2. Admin attempts to self-approve their own request
    review_resp = await client.post(
        f"/api/v1/access/requests/{admin_req_id}/review",
        json={"decision": "approved", "comment": "Self approval attempt"},
        headers=admin_headers,
    )
    # Must be rejected with 403 Forbidden!
    assert review_resp.status_code == 403
    assert "Self-approval forbidden" in review_resp.json()["detail"]

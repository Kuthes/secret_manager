import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from apps.api.app.core.security import create_access_token, get_password_hash
from apps.api.app.db.session import Base, get_db
from apps.api.app.main import app
from apps.api.app.models.dynamic_secret import DynamicSecretProvider
from apps.api.app.models.integration import IntegrationConnection
from apps.api.app.models.pam import AccessRequest, AccessResource
from apps.api.app.models.user import (
    Environment,
    Organization,
    OrganizationMembership,
    Project,
    Role,
    User,
)
from apps.api.app.services.kms_service import kms_service
from apps.api.app.services.pki_service import pki_service
from apps.api.app.services.secret_service import secret_service

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture
async def test_env():
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        # Organization A
        user_a = User(
            email=f"alice_{uuid.uuid4().hex[:6]}@orga.com",
            hashed_password=get_password_hash("SecretPass123!"),
            full_name="Alice OrgA",
            is_active=True,
            is_verified=True,
        )
        db.add(user_a)
        org_a = Organization(name="Tenant Alpha", slug=f"tenant-alpha-{uuid.uuid4().hex[:6]}")
        db.add(org_a)
        await db.flush()

        role_owner_a = Role(organization_id=org_a.id, name="Owner", slug="owner", is_system=True)
        db.add(role_owner_a)
        await db.flush()

        mem_a = OrganizationMembership(organization_id=org_a.id, user_id=user_a.id, role_id=role_owner_a.id)
        db.add(mem_a)

        proj_a = Project(organization_id=org_a.id, name="Alpha Core", slug="alpha-core")
        db.add(proj_a)
        await db.flush()

        env_a = Environment(project_id=proj_a.id, name="Production", slug="production")
        db.add(env_a)
        await db.flush()

        # Organization B
        user_b = User(
            email=f"bob_{uuid.uuid4().hex[:6]}@orgb.com",
            hashed_password=get_password_hash("SecretPass123!"),
            full_name="Bob OrgB",
            is_active=True,
            is_verified=True,
        )
        db.add(user_b)
        org_b = Organization(name="Tenant Beta", slug=f"tenant-beta-{uuid.uuid4().hex[:6]}")
        db.add(org_b)
        await db.flush()

        role_owner_b = Role(organization_id=org_b.id, name="Owner", slug="owner", is_system=True)
        db.add(role_owner_b)
        await db.flush()

        mem_b = OrganizationMembership(organization_id=org_b.id, user_id=user_b.id, role_id=role_owner_b.id)
        db.add(mem_b)

        proj_b = Project(organization_id=org_b.id, name="Beta Core", slug="beta-core")
        db.add(proj_b)
        await db.flush()

        env_b = Environment(project_id=proj_b.id, name="Production", slug="production")
        db.add(env_b)
        await db.flush()

        # Create Org A Resources
        secret_a = await secret_service.create_secret(
            db=db,
            project_id=proj_a.id,
            environment_id=env_a.id,
            key="ALPHA_STRIPE_KEY",
            value="TESTONLY_sk_test_alpha_12345",
            actor_id=user_a.id,
            actor_name=user_a.full_name,
        )

        ca_a = await pki_service.create_ca(
            db=db,
            organization_id=org_a.id,
            name="Alpha Root CA",
            common_name="Alpha Root Authority",
            actor_id=user_a.id,
            actor_name=user_a.full_name,
        )

        cert_a, _ = await pki_service.issue_certificate(
            db=db,
            ca_id=ca_a.id,
            common_name="api.alpha.internal",
            san_dns_names=["api.alpha.internal"],
            actor_id=user_a.id,
            actor_name=user_a.full_name,
        )

        key_a = await kms_service.create_key(
            db=db,
            organization_id=org_a.id,
            project_id=proj_a.id,
            name="alpha-kms-key",
            algorithm="AES-256-GCM",
            key_usage="ENCRYPT_DECRYPT",
            actor_id=user_a.id,
            actor_name=user_a.full_name,
        )

        pam_res_a = AccessResource(
            organization_id=org_a.id,
            project_id=proj_a.id,
            name="Alpha Production DB",
            resource_type="database",
            resource_identifier="postgres://alpha-db.internal:5432/db",
        )
        db.add(pam_res_a)
        await db.flush()

        pam_req_a = AccessRequest(
            resource_id=pam_res_a.id,
            requester_id=user_a.id,
            justification="Alpha maintenance",
            duration_seconds=3600,
            status="pending",
        )
        db.add(pam_req_a)

        conn_a = IntegrationConnection(
            organization_id=org_a.id,
            name="Alpha GitHub Actions",
            provider_type="github",
            credentials_encrypted="enc_creds",
        )
        db.add(conn_a)

        dyn_prov_a = DynamicSecretProvider(
            project_id=proj_a.id,
            environment_id=env_a.id,
            name="alpha-db-dynamic",
            provider_type="database",
            config_encrypted="{}",
            default_ttl_seconds=3600,
            max_ttl_seconds=86400,
        )
        db.add(dyn_prov_a)

        # Create Org B Resources
        secret_b = await secret_service.create_secret(
            db=db,
            project_id=proj_b.id,
            environment_id=env_b.id,
            key="BETA_STRIPE_KEY",
            value="TESTONLY_sk_test_beta_67890",
            actor_id=user_b.id,
            actor_name=user_b.full_name,
        )

        ca_b = await pki_service.create_ca(
            db=db,
            organization_id=org_b.id,
            name="Beta Root CA",
            common_name="Beta Root Authority",
            actor_id=user_b.id,
            actor_name=user_b.full_name,
        )

        cert_b, _ = await pki_service.issue_certificate(
            db=db,
            ca_id=ca_b.id,
            common_name="api.beta.internal",
            san_dns_names=["api.beta.internal"],
            actor_id=user_b.id,
            actor_name=user_b.full_name,
        )

        key_b = await kms_service.create_key(
            db=db,
            organization_id=org_b.id,
            project_id=proj_b.id,
            name="beta-kms-key",
            algorithm="AES-256-GCM",
            key_usage="ENCRYPT_DECRYPT",
            actor_id=user_b.id,
            actor_name=user_b.full_name,
        )

        await db.commit()

        token_a = create_access_token(subject=str(user_a.id), org_id=str(org_a.id))
        token_b = create_access_token(subject=str(user_b.id), org_id=str(org_b.id))

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
            "user_a": user_a, "org_a": org_a, "proj_a": proj_a, "env_a": env_a,
            "secret_a": secret_a, "ca_a": ca_a, "cert_a": cert_a, "key_a": key_a,
            "pam_res_a": pam_res_a, "pam_req_a": pam_req_a, "conn_a": conn_a, "dyn_prov_a": dyn_prov_a,
            "token_a": token_a,
            "user_b": user_b, "org_b": org_b, "proj_b": proj_b, "env_b": env_b,
            "secret_b": secret_b, "ca_b": ca_b, "cert_b": cert_b, "key_b": key_b,
            "token_b": token_b,
        }

    app.dependency_overrides.clear()
    await engine.dispose()


@pytest.mark.asyncio
async def test_cross_tenant_secret_access_blocked(test_env):
    t = test_env
    client = t["client"]

    # User B attempts to list secrets in Org A project
    resp = await client.get(
        f"/api/v1/secrets?project_id={t['proj_a'].id}&environment_id={t['env_a'].id}",
        headers={"Authorization": f"Bearer {t['token_b']}", "X-Organization-Id": str(t["org_b"].id)},
    )
    assert resp.status_code == 404

    # User B attempts to create secret in Org A project
    resp = await client.post(
        f"/api/v1/secrets?project_id={t['proj_a'].id}&environment_id={t['env_a'].id}",
        json={"key": "MALICIOUS_KEY", "value": "payload"},
        headers={"Authorization": f"Bearer {t['token_b']}", "X-Organization-Id": str(t["org_b"].id)},
    )
    assert resp.status_code == 404

    # User B attempts to create secret in Org B project with Org A environment (mismatched tenant environment ID)
    resp = await client.post(
        f"/api/v1/secrets?project_id={t['proj_b'].id}&environment_id={t['env_a'].id}",
        json={"key": "MALICIOUS_KEY_2", "value": "payload"},
        headers={"Authorization": f"Bearer {t['token_b']}", "X-Organization-Id": str(t["org_b"].id)},
    )
    assert resp.status_code == 404

    # User B attempts to reveal Org A secret
    resp = await client.get(
        f"/api/v1/secrets/{t['secret_a'].id}/reveal",
        headers={"Authorization": f"Bearer {t['token_b']}", "X-Organization-Id": str(t["org_b"].id)},
    )
    assert resp.status_code == 404

    # User B attempts to reveal Org A secret via key lookup (/value)
    resp = await client.get(
        f"/api/v1/secrets/value?project_id={t['proj_a'].id}&environment_id={t['env_a'].id}&key=ALPHA_STRIPE_KEY",
        headers={"Authorization": f"Bearer {t['token_b']}", "X-Organization-Id": str(t["org_b"].id)},
    )
    assert resp.status_code == 404

    # User B attempts to update Org A secret
    resp = await client.put(
        f"/api/v1/secrets/{t['secret_a'].id}",
        json={"value": "hacked_by_bob"},
        headers={"Authorization": f"Bearer {t['token_b']}", "X-Organization-Id": str(t["org_b"].id)},
    )
    assert resp.status_code == 404

    # User B attempts to delete Org A secret
    resp = await client.delete(
        f"/api/v1/secrets/{t['secret_a'].id}",
        headers={"Authorization": f"Bearer {t['token_b']}", "X-Organization-Id": str(t["org_b"].id)},
    )
    assert resp.status_code == 404

    # User B attempts to view Org A secret versions
    resp = await client.get(
        f"/api/v1/secrets/{t['secret_a'].id}/versions",
        headers={"Authorization": f"Bearer {t['token_b']}", "X-Organization-Id": str(t["org_b"].id)},
    )
    assert resp.status_code == 404

    # User B attempts rollback on Org A secret
    resp = await client.post(
        f"/api/v1/secrets/{t['secret_a'].id}/rollback",
        json={"target_version": 1, "reason": "malicious rollback"},
        headers={"Authorization": f"Bearer {t['token_b']}", "X-Organization-Id": str(t["org_b"].id)},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_cross_tenant_pki_blocked(test_env):
    t = test_env
    client = t["client"]

    # User B attempts to issue cert from Org A CA
    resp = await client.post(
        "/api/v1/pki/issue",
        json={
            "ca_id": str(t["ca_a"].id),
            "common_name": "hacked.alpha.internal",
            "san_dns_names": ["hacked.alpha.internal"],
            "validity_days": 30,
        },
        headers={"Authorization": f"Bearer {t['token_b']}", "X-Organization-Id": str(t["org_b"].id)},
    )
    assert resp.status_code == 404

    # User B attempts to revoke Org A cert
    resp = await client.post(
        f"/api/v1/pki/certificates/{t['cert_a'].id}/revoke",
        json={"reason": "malicious_revocation"},
        headers={"Authorization": f"Bearer {t['token_b']}", "X-Organization-Id": str(t["org_b"].id)},
    )
    assert resp.status_code == 404

    # User B attempts to download Org A cert private key
    resp = await client.get(
        f"/api/v1/pki/certificates/{t['cert_a'].id}/private-key",
        headers={"Authorization": f"Bearer {t['token_b']}", "X-Organization-Id": str(t["org_b"].id)},
    )
    assert resp.status_code == 404

    # User B attempts to fetch Org A CA CRL
    resp = await client.get(
        f"/api/v1/pki/ca/{t['ca_a'].id}/crl",
        headers={"Authorization": f"Bearer {t['token_b']}", "X-Organization-Id": str(t["org_b"].id)},
    )
    assert resp.status_code == 404

    # User B attempts to create intermediate CA referencing Org A CA as parent
    resp = await client.post(
        "/api/v1/pki/ca",
        json={
            "name": "Beta Intermediate",
            "common_name": "Beta Intermediate CA",
            "ca_type": "intermediate",
            "parent_ca_id": str(t["ca_a"].id),
            "validity_days": 365,
        },
        headers={"Authorization": f"Bearer {t['token_b']}", "X-Organization-Id": str(t["org_b"].id)},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_cross_tenant_kms_blocked(test_env):
    t = test_env
    client = t["client"]

    # User B attempts to encrypt with Org A KMS key
    resp = await client.post(
        f"/api/v1/kms/keys/{t['key_a'].id}/encrypt",
        json={"plaintext": "classified_payload"},
        headers={"Authorization": f"Bearer {t['token_b']}", "X-Organization-Id": str(t["org_b"].id)},
    )
    assert resp.status_code == 404

    # User B attempts to decrypt with Org A KMS key
    resp = await client.post(
        f"/api/v1/kms/keys/{t['key_a'].id}/decrypt",
        json={"ciphertext": "QUFBQUFBQUFBQUFBQUFBQUFBQUE=", "nonce": "QUFBQUFBQUFBQUFB", "version": 1},
        headers={"Authorization": f"Bearer {t['token_b']}", "X-Organization-Id": str(t["org_b"].id)},
    )
    assert resp.status_code == 404

    # User B attempts to rotate Org A KMS key
    resp = await client.post(
        f"/api/v1/kms/keys/{t['key_a'].id}/rotate",
        headers={"Authorization": f"Bearer {t['token_b']}", "X-Organization-Id": str(t["org_b"].id)},
    )
    assert resp.status_code == 404

    # User B attempts to disable Org A KMS key
    resp = await client.post(
        f"/api/v1/kms/keys/{t['key_a'].id}/disable",
        headers={"Authorization": f"Bearer {t['token_b']}", "X-Organization-Id": str(t["org_b"].id)},
    )
    assert resp.status_code == 404

    # User B attempts to sign with Org A KMS key
    resp = await client.post(
        f"/api/v1/kms/keys/{t['key_a'].id}/sign",
        json={"message": "tampered message"},
        headers={"Authorization": f"Bearer {t['token_b']}", "X-Organization-Id": str(t["org_b"].id)},
    )
    assert resp.status_code == 404

    # User B attempts to verify with Org A KMS key
    resp = await client.post(
        f"/api/v1/kms/keys/{t['key_a'].id}/verify",
        json={"message": "tampered message", "signature": "QUFBQQ=="},
        headers={"Authorization": f"Bearer {t['token_b']}", "X-Organization-Id": str(t["org_b"].id)},
    )
    assert resp.status_code == 404

    # User B attempts to create key associated with Org A project ID
    resp = await client.post(
        "/api/v1/kms/keys",
        json={"name": "rogue-key", "algorithm": "AES-256-GCM", "key_usage": "ENCRYPT_DECRYPT", "project_id": str(t["proj_a"].id)},
        headers={"Authorization": f"Bearer {t['token_b']}", "X-Organization-Id": str(t["org_b"].id)},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_cross_tenant_pam_blocked(test_env):
    t = test_env
    client = t["client"]

    # User B attempts to request access to Org A PAM resource
    resp = await client.post(
        "/api/v1/access/requests",
        json={
            "resource_id": str(t["pam_res_a"].id),
            "justification": "Cross tenant attack",
            "duration_seconds": 3600,
        },
        headers={"Authorization": f"Bearer {t['token_b']}", "X-Organization-Id": str(t["org_b"].id)},
    )
    assert resp.status_code == 404

    # User B attempts to review/approve Org A PAM request
    resp = await client.post(
        f"/api/v1/access/requests/{t['pam_req_a'].id}/review",
        json={"decision": "approved", "comment": "Illegitimate approval"},
        headers={"Authorization": f"Bearer {t['token_b']}", "X-Organization-Id": str(t["org_b"].id)},
    )
    assert resp.status_code == 404

    # User B attempts to revoke Org A PAM request
    resp = await client.post(
        f"/api/v1/access/requests/{t['pam_req_a'].id}/revoke",
        headers={"Authorization": f"Bearer {t['token_b']}", "X-Organization-Id": str(t["org_b"].id)},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_cross_tenant_dynamic_and_integrations_blocked(test_env):
    t = test_env
    client = t["client"]

    # User B attempts to issue lease from Org A dynamic provider
    resp = await client.post(
        f"/api/v1/dynamic/providers/{t['dyn_prov_a'].id}/issue",
        json={"ttl_seconds": 1800},
        headers={"Authorization": f"Bearer {t['token_b']}", "X-Organization-Id": str(t["org_b"].id)},
    )
    assert resp.status_code == 404

    # User B attempts to create dynamic provider with Org A project
    resp = await client.post(
        "/api/v1/dynamic/providers",
        json={
            "project_id": str(t["proj_a"].id),
            "environment_id": str(t["env_a"].id),
            "name": "rogue-dyn-provider",
            "provider_type": "database",
            "config": {},
        },
        headers={"Authorization": f"Bearer {t['token_b']}", "X-Organization-Id": str(t["org_b"].id)},
    )
    assert resp.status_code == 404

    # User B attempts to create secret sync with Org A connection
    resp = await client.post(
        "/api/v1/integrations/syncs",
        json={
            "project_id": str(t["proj_b"].id),
            "environment_id": str(t["env_b"].id),
            "connection_id": str(t["conn_a"].id),
            "target_path": "/var/secrets",
        },
        headers={"Authorization": f"Bearer {t['token_b']}", "X-Organization-Id": str(t["org_b"].id)},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_foreign_uuid_swapping_matrix(test_env):
    """Systematically test swapping valid foreign UUIDs across all sensitive endpoints."""
    t = test_env
    client = t["client"]

    # Authenticated as Org A, try querying with Org B valid IDs
    foreign_endpoints = [
        ("GET", f"/api/v1/secrets/{t['secret_b'].id}/reveal", None),
        ("PUT", f"/api/v1/secrets/{t['secret_b'].id}", {"value": "swap_attempt"}),
        ("DELETE", f"/api/v1/secrets/{t['secret_b'].id}", None),
        ("GET", f"/api/v1/pki/certificates/{t['cert_b'].id}/private-key", None),
        ("POST", f"/api/v1/pki/certificates/{t['cert_b'].id}/revoke", {"reason": "test"}),
        ("POST", f"/api/v1/kms/keys/{t['key_b'].id}/encrypt", {"plaintext": "swap_test"}),
        ("POST", f"/api/v1/kms/keys/{t['key_b'].id}/rotate", None),
        ("GET", f"/api/v1/projects/{t['proj_b'].id}/environments", None),
    ]

    for method, url, payload in foreign_endpoints:
        if method == "GET":
            resp = await client.get(url, headers={"Authorization": f"Bearer {t['token_a']}", "X-Organization-Id": str(t["org_a"].id)})
        elif method == "POST":
            resp = await client.post(url, json=payload, headers={"Authorization": f"Bearer {t['token_a']}", "X-Organization-Id": str(t["org_a"].id)})
        elif method == "PUT":
            resp = await client.put(url, json=payload, headers={"Authorization": f"Bearer {t['token_a']}", "X-Organization-Id": str(t["org_a"].id)})
        elif method == "DELETE":
            resp = await client.delete(url, headers={"Authorization": f"Bearer {t['token_a']}", "X-Organization-Id": str(t["org_a"].id)})
        
        assert resp.status_code == 404, f"Failed UUID swap isolation on {method} {url}, got {resp.status_code}"


@pytest.mark.asyncio
async def test_header_forgery_spoofing_rejected(test_env):
    t = test_env
    client = t["client"]

    # User B attempts to spoof X-Organization-Id to Org A
    resp = await client.get(
        "/api/v1/projects",
        headers={"Authorization": f"Bearer {t['token_b']}", "X-Organization-Id": str(t["org_a"].id)},
    )
    assert resp.status_code == 403

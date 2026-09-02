import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from apps.api.app.main import app
from apps.api.app.db.session import Base, get_db
from apps.api.app.services.seed_service import seed_service

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture
async def test_db():
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with async_session() as session:
        await seed_service.seed_demo_data(session)
        yield session

    await engine.dispose()


@pytest_asyncio.fixture
async def client(test_db):
    async def override_get_db():
        yield test_db

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_auth_and_secret_lifecycle(client: AsyncClient):
    # 1. Login with demo credentials
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "demo@aegisvault.local", "password": "AegisDemo2026!"},
    )
    assert login_resp.status_code == 200
    token_data = login_resp.json()
    token = token_data["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Get projects and environments
    proj_resp = await client.get("/api/v1/projects", headers=headers)
    assert proj_resp.status_code == 200
    projects = proj_resp.json()
    assert len(projects) >= 1
    project_id = projects[0]["id"]
    environments = projects[0]["environments"]
    prod_env = next(e for e in environments if e["slug"] == "production")
    env_id = prod_env["id"]

    # 3. List secrets (verify plaintext is NEVER present)
    secrets_resp = await client.get(
        f"/api/v1/secrets?project_id={project_id}&environment_id={env_id}",
        headers=headers,
    )
    assert secrets_resp.status_code == 200
    secrets_list = secrets_resp.json()
    assert len(secrets_list) >= 1
    # Check that no plaintext is in response
    for s in secrets_list:
        assert "value" not in s
        assert "encrypted_value" not in s

    # 4. Create new secret
    create_resp = await client.post(
        f"/api/v1/secrets?project_id={project_id}&environment_id={env_id}",
        headers=headers,
        json={
            "key": "TEST_INTEGRATION_KEY",
            "value": "super_secret_payload_value_999",
            "path": "/testing",
            "comment": "Integration test secret",
        },
    )
    assert create_resp.status_code == 201
    created_secret = create_resp.json()
    secret_id = created_secret["id"]
    assert created_secret["key"] == "TEST_INTEGRATION_KEY"
    assert created_secret["current_version"] == 1

    # 5. Reveal secret via dedicated reveal API
    reveal_resp = await client.get(
        f"/api/v1/secrets/{secret_id}/reveal",
        headers=headers,
    )
    assert reveal_resp.status_code == 200
    revealed = reveal_resp.json()
    assert revealed["value"] == "super_secret_payload_value_999"

    # 6. Update secret (Version 2)
    update_resp = await client.put(
        f"/api/v1/secrets/{secret_id}",
        headers=headers,
        json={"value": "updated_secret_payload_value_888", "change_message": "Rotating test key"},
    )
    assert update_resp.status_code == 200
    assert update_resp.json()["current_version"] == 2

    # 7. Check version history
    ver_resp = await client.get(f"/api/v1/secrets/{secret_id}/versions", headers=headers)
    assert ver_resp.status_code == 200
    versions = ver_resp.json()
    assert len(versions) == 2
    assert versions[0]["version"] == 2
    assert versions[1]["version"] == 1

    # 8. Rollback to Version 1
    rollback_resp = await client.post(
        f"/api/v1/secrets/{secret_id}/rollback",
        headers=headers,
        json={"target_version": 1, "reason": "Accidental update"},
    )
    assert rollback_resp.status_code == 200
    assert rollback_resp.json()["current_version"] == 3

    # 9. Verify revealed value matches Version 1
    reveal_v3 = await client.get(f"/api/v1/secrets/{secret_id}/reveal", headers=headers)
    assert reveal_v3.json()["value"] == "super_secret_payload_value_999"

    # 10. KMS Key & Cryptographic Operations
    kms_keys = await client.get("/api/v1/kms/keys", headers=headers)
    assert kms_keys.status_code == 200
    keys = kms_keys.json()
    assert len(keys) >= 1
    aes_key = next(k for k in keys if k["algorithm"] == "AES-256-GCM")

    enc_resp = await client.post(
        f"/api/v1/kms/keys/{aes_key['id']}/encrypt",
        headers=headers,
        json={"plaintext": "confidential_customer_ssn_1234"},
    )
    assert enc_resp.status_code == 200
    enc_data = enc_resp.json()

    dec_resp = await client.post(
        f"/api/v1/kms/keys/{aes_key['id']}/decrypt",
        headers=headers,
        json={"ciphertext": enc_data["ciphertext"], "nonce": enc_data["nonce"]},
    )
    assert dec_resp.status_code == 200
    assert dec_resp.json()["plaintext"] == "confidential_customer_ssn_1234"

    # 11. PKI Certificate Issuance
    ca_resp = await client.get("/api/v1/pki/ca", headers=headers)
    assert ca_resp.status_code == 200
    cas = ca_resp.json()
    assert len(cas) >= 1
    ca_id = cas[0]["id"]

    issue_resp = await client.post(
        "/api/v1/pki/issue",
        headers=headers,
        json={
            "ca_id": ca_id,
            "common_name": "checkout.prod.acme.dev",
            "san_dns_names": ["checkout.prod.acme.dev", "payments.prod.acme.dev"],
            "validity_days": 60,
        },
    )
    assert issue_resp.status_code == 201
    issued_cert = issue_resp.json()
    assert "BEGIN CERTIFICATE" in issued_cert["cert_pem"]
    assert "BEGIN PRIVATE KEY" in issued_cert["private_key_pem"]

    # 12. Audit Log Verification
    audit_resp = await client.get("/api/v1/audit/events", headers=headers)
    assert audit_resp.status_code == 200
    audit_events = audit_resp.json()
    assert len(audit_events) > 0
    # Confirm actions exist in tamper-evident chain
    actions = [e["action"] for e in audit_events]
    assert "secret.create" in actions
    assert "secret.reveal" in actions
    assert "secret.rollback" in actions

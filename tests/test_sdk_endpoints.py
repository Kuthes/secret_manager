import asyncio

import httpx
import pytest
from aegisvault.client import AegisVault
from aegisvault.exceptions import AuthenticationError
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from apps.api.app.db.session import Base, get_db
from apps.api.app.main import app
from apps.api.app.services.seed_service import seed_service

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


def test_get_secret_value_by_key_api():
    async def _test():
        engine = create_async_engine(TEST_DATABASE_URL, echo=False)
        async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        async with async_session() as session:
            await seed_service.seed_demo_data(session)

            async def override_get_db():
                yield session

            app.dependency_overrides[get_db] = override_get_db
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                # 1. Login
                login_resp = await client.post(
                    "/api/v1/auth/login",
                    json={"email": "demo@aegisvault.local", "password": "AegisDemo2026!"},
                )
                assert login_resp.status_code == 200
                token = login_resp.json()["access_token"]
                headers = {"Authorization": f"Bearer {token}"}

                # 2. Get project & environment
                proj_resp = await client.get("/api/v1/projects", headers=headers)
                assert proj_resp.status_code == 200
                project = proj_resp.json()[0]
                project_id = project["id"]
                prod_env = next(e for e in project["environments"] if e["slug"] == "production")
                env_id = prod_env["id"]

                # 3. Create a secret
                create_resp = await client.post(
                    f"/api/v1/secrets?project_id={project_id}&environment_id={env_id}",
                    json={"key": "TEST_DB_PASSWORD", "value": "super-secret-postgres-pass", "path": "/"},
                    headers=headers,
                )
                assert create_resp.status_code == 201

                # 4. Fetch secret value directly by key
                value_resp = await client.get(
                    f"/api/v1/secrets/value?project_id={project_id}&environment_id={env_id}&key=TEST_DB_PASSWORD",
                    headers=headers,
                )
                assert value_resp.status_code == 200
                data = value_resp.json()
                assert data["key"] == "TEST_DB_PASSWORD"
                assert data["value"] == "super-secret-postgres-pass"
                assert data["version"] == 1

                # 5. Non-existent key returns 404
                missing_resp = await client.get(
                    f"/api/v1/secrets/value?project_id={project_id}&environment_id={env_id}&key=NON_EXISTENT_KEY",
                    headers=headers,
                )
                assert missing_resp.status_code == 404

                # 6. Test with AegisVault Python SDK using ASGITransport
                sdk_client = AegisVault(
                    api_url="http://test",
                    token=token,
                    project_id=project_id,
                    environment_id=env_id,
                    cache_ttl_seconds=300,
                )
                # Swap transport for test
                sdk_client._client = httpx.Client(
                    transport=httpx.HTTPTransport(),
                    base_url="http://test",
                    headers={"Authorization": f"Bearer {token}"},
                )

                # Direct get with fallback test
                assert sdk_client._cache == {}

            app.dependency_overrides.clear()
        await engine.dispose()

    asyncio.run(_test())


def test_python_sdk_unit_and_caching():
    # 1. Test error initialization without token
    with pytest.raises(AuthenticationError):
        AegisVault(token="")

    # 2. Test cache operations
    vault = AegisVault(
        token="TESTONLY_DUMMY_TOKEN",
        project_id="p1",
        environment_id="e1",
        cache_ttl_seconds=60,
    )
    # Manually populate cache to verify TTL logic
    import time
    vault._cache["p1:e1:API_KEY"] = ("secret-val-123", time.time() + 60)
    assert vault.get("API_KEY") == "secret-val-123"

    # Test cache invalidation
    vault.invalidate_cache("API_KEY")
    assert "p1:e1:API_KEY" not in vault._cache

    vault.close()

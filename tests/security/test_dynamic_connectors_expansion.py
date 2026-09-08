
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from apps.api.app.core.dynamic_engines import (
    MongoDBEngine,
    MySQLEngine,
    PostgreSQLEngine,
    RedisACLEngine,
    get_dynamic_engine,
)
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

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest.mark.asyncio
async def test_engine_unit_generation_and_revocation():
    # 1. PostgreSQL Engine
    pg = get_dynamic_engine("postgres")
    assert isinstance(pg, PostgreSQLEngine)
    pg_creds, pg_meta = pg.generate_credentials({"database": "app_prod", "roles": ["SELECT", "INSERT"]}, 3600)
    assert pg_creds["engine"] == "postgresql"
    assert pg_creds["username"].startswith("aegis_pg_")
    assert "CREATE ROLE aegis_pg_" in pg_meta["creation_statements"][0]
    assert "DROP ROLE IF EXISTS" in pg_meta["revocation_plan"]["statements"][2]

    # 2. MySQL Engine
    my = get_dynamic_engine("mysql")
    assert isinstance(my, MySQLEngine)
    my_creds, my_meta = my.generate_credentials({"database": "orders_db", "host_pattern": "%"}, 1800)
    assert my_creds["engine"] == "mysql"
    assert my_creds["username"].startswith("aegis_my_")
    assert "CREATE USER" in my_meta["creation_statements"][0]
    assert "DROP USER IF EXISTS" in my_meta["revocation_plan"]["statements"][1]

    # 3. MongoDB Engine
    mongo = get_dynamic_engine("mongodb")
    assert isinstance(mongo, MongoDBEngine)
    mongo_creds, mongo_meta = mongo.generate_credentials({"database": "analytics"}, 7200)
    assert mongo_creds["engine"] == "mongodb"
    assert mongo_creds["username"].startswith("aegis_mongo_")
    assert mongo_meta["command"] == "createUser"
    assert mongo_meta["revocation_plan"]["command"] == "dropUser"

    # 4. Redis Engine
    redis = get_dynamic_engine("redis")
    assert isinstance(redis, RedisACLEngine)
    rd_creds, rd_meta = redis.generate_credentials({"allowed_keys": ["cache:*"], "allowed_commands": ["+get", "+set"]}, 900)
    assert rd_creds["engine"] == "redis"
    assert rd_creds["username"].startswith("aegis_rd_")
    assert "ACL SETUSER aegis_rd_" in rd_meta["command"]
    assert "cache:*" in rd_meta["command"]
    assert "ACL DELUSER aegis_rd_" in rd_meta["revocation_plan"]["command"]


@pytest_asyncio.fixture
async def dynamic_env():
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        org = Organization(name="Dynamic Corp", slug="dynamic-corp")
        db.add(org)
        await db.flush()

        role = Role(organization_id=org.id, name="Owner", slug="owner", is_system=True)
        db.add(role)
        await db.flush()

        user = User(
            email="dynamic_admin@dynamiccorp.com",
            hashed_password=get_password_hash("DynamicPass123!"),
            full_name="Dynamic Admin",
        )
        db.add(user)
        await db.flush()

        mem = OrganizationMembership(organization_id=org.id, user_id=user.id, role_id=role.id)
        db.add(mem)

        proj = Project(organization_id=org.id, name="Cloud Infrastructure", slug="cloud-infra")
        db.add(proj)
        await db.flush()

        env = Environment(project_id=proj.id, name="Staging", slug="staging")
        db.add(env)
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
        token = create_access_token(subject=str(user.id), org_id=str(org.id))
        yield {
            "client": client,
            "org": org,
            "user": user,
            "project": proj,
            "environment": env,
            "token": token,
        }

    app.dependency_overrides.clear()
    await engine.dispose()


@pytest.mark.asyncio
async def test_dynamic_provider_and_lease_lifecycle_all_engines(dynamic_env):
    t = dynamic_env
    client = t["client"]
    token = t["token"]
    headers = {"Authorization": f"Bearer {token}"}

    engine_configs = [
        ("postgres", {"database": "pg_app", "roles": ["SELECT"]}),
        ("mysql", {"database": "my_shop", "host_pattern": "%"}),
        ("mongodb", {"database": "mongo_logs"}),
        ("redis", {"allowed_keys": ["session:*"], "allowed_commands": ["+@read"]}),
    ]

    for engine_type, config in engine_configs:
        # 1. Create Dynamic Provider
        create_resp = await client.post(
            "/api/v1/dynamic/providers",
            json={
                "project_id": str(t["project"].id),
                "environment_id": str(t["environment"].id),
                "name": f"test-{engine_type}-provider",
                "provider_type": engine_type,
                "default_ttl_seconds": 3600,
                "max_ttl_seconds": 7200,
                "config": config,
            },
            headers=headers,
        )
        assert create_resp.status_code == 201
        provider_data = create_resp.json()
        provider_id = provider_data["id"]

        # 2. Issue Lease
        issue_resp = await client.post(
            f"/api/v1/dynamic/providers/{provider_id}/issue",
            json={"ttl_seconds": 1800},
            headers=headers,
        )
        assert issue_resp.status_code == 201
        lease_data = issue_resp.json()
        assert lease_data["status"] == "active"
        assert lease_data["ttl_seconds"] == 1800
        assert "username" in lease_data["credentials"]
        assert "password" in lease_data["credentials"]
        assert lease_data["credentials"]["engine"] == (
            "postgresql" if engine_type == "postgres" else engine_type
        )
        lease_id = lease_data["id"]

        # 3. Revoke Lease
        revoke_resp = await client.post(
            f"/api/v1/dynamic/leases/{lease_id}/revoke",
            headers=headers,
        )
        assert revoke_resp.status_code == 200
        assert revoke_resp.json()["status"] == "revoked"


@pytest.mark.asyncio
async def test_unsupported_engine_type_rejected(dynamic_env):
    t = dynamic_env
    client = t["client"]
    token = t["token"]
    headers = {"Authorization": f"Bearer {token}"}

    bad_resp = await client.post(
        "/api/v1/dynamic/providers",
        json={
            "project_id": str(t["project"].id),
            "environment_id": str(t["environment"].id),
            "name": "unsupported-provider",
            "provider_type": "invalid_engine_name",
            "default_ttl_seconds": 3600,
            "max_ttl_seconds": 7200,
            "config": {},
        },
        headers=headers,
    )
    assert bad_resp.status_code == 400
    assert "Unsupported dynamic provider type" in bad_resp.json()["detail"]

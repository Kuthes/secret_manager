import json
import pytest
import pytest_asyncio
import uuid
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from apps.api.app.db.session import Base
from apps.api.app.models.user import Organization
from apps.api.app.models.audit import AuditEvent
from apps.api.app.services.audit_service import audit_service, GENESIS_HASH

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture
async def audit_env():
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        org = Organization(name="Audit Immutable Corp", slug="audit-corp")
        db.add(org)
        await db.commit()

        yield {
            "session_factory": session_factory,
            "org": org,
        }

    await engine.dispose()


@pytest.mark.asyncio
async def test_genesis_and_chain_integrity(audit_env):
    t = audit_env
    async with t["session_factory"]() as db:
        # First event gets GENESIS_HASH
        e1 = await audit_service.log_event(
            db=db,
            organization_id=t["org"].id,
            action="secret.create",
            resource_type="secret",
            actor_name="Alice",
            metadata={"key": "STRIPE_KEY"},
        )
        assert e1.prev_event_hash == GENESIS_HASH
        assert len(e1.event_hash) == 64

        # Second event links to e1
        e2 = await audit_service.log_event(
            db=db,
            organization_id=t["org"].id,
            action="secret.reveal",
            resource_type="secret",
            actor_name="Bob",
            metadata={"justification": "Incident response"},
        )
        assert e2.prev_event_hash == e1.event_hash

        # Third event links to e2
        e3 = await audit_service.log_event(
            db=db,
            organization_id=t["org"].id,
            action="secret.update",
            resource_type="secret",
            actor_name="Charlie",
        )
        assert e3.prev_event_hash == e2.event_hash
        await db.commit()

        # Verify chain
        res = await audit_service.verify_chain(db=db, organization_id=t["org"].id)
        assert res["valid"] is True
        assert res["total_events"] == 3


@pytest.mark.asyncio
async def test_tampered_payload_detected(audit_env):
    t = audit_env
    async with t["session_factory"]() as db:
        e1 = await audit_service.log_event(
            db=db,
            organization_id=t["org"].id,
            action="user.login",
            resource_type="user",
            actor_name="Attacker",
        )
        e2 = await audit_service.log_event(
            db=db,
            organization_id=t["org"].id,
            action="secret.reveal",
            resource_type="secret",
            actor_name="Attacker",
        )
        await db.commit()

        # Malicious database manipulation: tamper action of e2 to hide secret reveal
        e2.action = "secret.list_view"
        await db.commit()

        # Verify chain detects modification
        res = await audit_service.verify_chain(db=db, organization_id=t["org"].id)
        assert res["valid"] is False
        assert res["corrupted_event_id"] == str(e2.id)
        assert "Tampered event data" in res["error"]


@pytest.mark.asyncio
async def test_deleted_event_chain_break_detected(audit_env):
    t = audit_env
    async with t["session_factory"]() as db:
        e1 = await audit_service.log_event(db=db, organization_id=t["org"].id, action="a1", resource_type="r")
        e2 = await audit_service.log_event(db=db, organization_id=t["org"].id, action="a2", resource_type="r")
        e3 = await audit_service.log_event(db=db, organization_id=t["org"].id, action="a3", resource_type="r")
        await db.commit()

        # Delete intermediate event e2
        await db.delete(e2)
        await db.commit()

        # Verify chain detects break
        res = await audit_service.verify_chain(db=db, organization_id=t["org"].id)
        assert res["valid"] is False
        assert res["corrupted_event_id"] == str(e3.id)
        assert "Hash chain break" in res["error"]


@pytest.mark.asyncio
async def test_sensitive_metadata_sanitization(audit_env):
    t = audit_env
    async with t["session_factory"]() as db:
        event = await audit_service.log_event(
            db=db,
            organization_id=t["org"].id,
            action="secret.create",
            resource_type="secret",
            metadata={
                "key": "DATABASE_PASS",
                "secret_value": "SUPER_SECRET_PLAINTEXT_123",
                "password_hash": "raw_pass",
                "safe_field": "metadata_only",
            },
        )
        assert "secret_value" not in event.metadata_json
        assert "password_hash" not in event.metadata_json
        assert event.metadata_json["safe_field"] == "metadata_only"


@pytest.mark.asyncio
async def test_audit_log_export(audit_env):
    t = audit_env
    async with t["session_factory"]() as db:
        await audit_service.log_event(db=db, organization_id=t["org"].id, action="export.test", resource_type="audit")
        await db.commit()

        # JSON Export
        json_export = await audit_service.export_events(db=db, organization_id=t["org"].id, format_type="json")
        parsed = json.loads(json_export)
        assert len(parsed) >= 1
        assert parsed[0]["action"] == "export.test"

        # CSV Export
        csv_export = await audit_service.export_events(db=db, organization_id=t["org"].id, format_type="csv")
        assert "timestamp,action,actor_name" in csv_export
        assert "export.test" in csv_export

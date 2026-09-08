import pytest
import uuid
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from apps.api.app.core.config import settings
from apps.api.app.db.session import Base
from apps.api.app.core.crypto import EnvelopeCryptoEngine
from apps.api.app.core.kms_provider import LocalKMSProvider
from apps.api.app.core.security import verify_password, get_password_hash
from apps.api.app.models.user import User, Organization, Role, OrganizationMembership, Project, Environment
from apps.api.app.models.secret import Secret, SecretVersion
from apps.api.app.models.pki import CertificateAuthority, Certificate
from apps.api.app.models.kms import ManagedKey
from apps.api.app.models.audit import AuditEvent
from apps.api.app.services.secret_service import secret_service
from apps.api.app.services.pki_service import pki_service
from apps.api.app.services.kms_service import kms_service
from apps.api.app.services.audit_service import audit_service


@pytest.mark.asyncio
async def test_full_disaster_recovery_lifecycle():
    """
    Simulates a total infrastructure catastrophe, database wipe, and cold-start restoration:
    1. Seed production assets (User, Org, Project, Secrets v1/v2, CA, Cert, KMS Key, Audit logs)
    2. Export encrypted backup snapshot
    3. Destroy the entire database (drop all tables)
    4. Re-provision database and restore records
    5. Re-inject Root MEK key material
    6. Verify complete operational and cryptographic integrity
    """
    # Master key material backed up securely
    MEK_ID = settings.MEK_ID
    MEK_KEY_B64 = settings.MASTER_ENCRYPTION_KEY

    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    # --- STEP 1: INITIAL SYSTEM POPULATION ---
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        # Org, Role, User
        org = Organization(name="Disaster Recovery Corp", slug="dr-corp")
        db.add(org)
        await db.flush()

        role = Role(organization_id=org.id, name="Owner", slug="owner", is_system=True)
        db.add(role)
        await db.flush()

        user = User(
            email="dr_admin@drcorp.com",
            hashed_password=get_password_hash("DRAdminUltraPass2026!"),
            full_name="DR Admin",
        )
        db.add(user)
        await db.flush()

        mem = OrganizationMembership(organization_id=org.id, user_id=user.id, role_id=role.id)
        db.add(mem)

        # Project & Environment
        proj = Project(organization_id=org.id, name="Payment Service", slug="payments")
        db.add(proj)
        await db.flush()

        env = Environment(project_id=proj.id, name="Production", slug="prod")
        db.add(env)
        await db.flush()

        # Secret v1 & v2
        secret = await secret_service.create_secret(
            db=db,
            project_id=proj.id,
            environment_id=env.id,
            key="PAYMENT_GATEWAY_TOKEN",
            value="TESTONLY_gateway_token_version_1_initial",
            comment="Primary Payment Gateway",
            actor_id=user.id,
            actor_name=user.full_name,
        )
        await db.commit()

    async with session_factory() as db:
        # Update to Version 2
        updated_secret = await secret_service.update_secret(
            db=db,
            secret_id=secret.id,
            value="TESTONLY_gateway_token_version_2_updated",
            comment="Rotated gateway token",
            actor_id=user.id,
            actor_name=user.full_name,
        )

        # PKI CA & Certificate
        ca = await pki_service.create_ca(
            db=db,
            organization_id=org.id,
            name="DR Root CA",
            common_name="dr-root-ca.internal",
            actor_id=user.id,
            actor_name=user.full_name,
        )

        cert, _ = await pki_service.issue_certificate(
            db=db,
            ca_id=ca.id,
            common_name="payments.drcorp.internal",
            san_dns_names=["payments.drcorp.internal"],
            actor_id=user.id,
            actor_name=user.full_name,
        )

        # KMS Key
        kms_key = await kms_service.create_key(
            db=db,
            organization_id=org.id,
            project_id=proj.id,
            name="dr-kms-key",
            algorithm="AES-256-GCM",
            key_usage="ENCRYPT_DECRYPT",
            actor_id=user.id,
            actor_name=user.full_name,
        )

        # Audit events
        e1 = await audit_service.log_event(
            db=db,
            organization_id=org.id,
            project_id=proj.id,
            action="secret.create",
            resource_type="secret",
            resource_id=str(secret.id),
            actor_id=user.id,
            actor_name=user.full_name,
        )
        e2 = await audit_service.log_event(
            db=db,
            organization_id=org.id,
            project_id=proj.id,
            action="secret.update",
            resource_type="secret",
            resource_id=str(secret.id),
            actor_id=user.id,
            actor_name=user.full_name,
        )
        await db.commit()

    # --- STEP 2: SIMULATE BACKUP SNAPSHOT EXPORT ---
    backup_data = {}
    async with session_factory() as db:
        for model, key_name in [
            (Organization, "organizations"),
            (Role, "roles"),
            (User, "users"),
            (OrganizationMembership, "memberships"),
            (Project, "projects"),
            (Environment, "environments"),
            (Secret, "secrets"),
            (SecretVersion, "secret_versions"),
            (CertificateAuthority, "cas"),
            (Certificate, "certificates"),
            (ManagedKey, "kms_keys"),
            (AuditEvent, "audit_events"),
        ]:
            res = await db.execute(select(model))
            backup_data[key_name] = res.scalars().all()

    # --- STEP 3: TOTAL DISASTER SIMULATION (DESTROY DATABASE) ---
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    # --- STEP 4: RESTORATION PROCEDURE ---
    # Recreate clean schema
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Restore records from backup snapshot
    async with session_factory() as db:
        for key_name in [
            "organizations",
            "roles",
            "users",
            "memberships",
            "projects",
            "environments",
            "secrets",
            "secret_versions",
            "cas",
            "certificates",
            "kms_keys",
            "audit_events",
        ]:
            for row in backup_data[key_name]:
                # Merge row into new session
                await db.merge(row)
        await db.commit()

    # --- STEP 5: RESTORE ROOT-OF-TRUST MEK & RE-INITIALIZE CRYPTO ---
    dr_provider = LocalKMSProvider(initial_key_b64=MEK_KEY_B64, initial_mek_id=MEK_ID)
    dr_crypto = EnvelopeCryptoEngine(provider=dr_provider)

    # --- STEP 6: POST-RESTORE VERIFICATION & INTEGRITY TESTS ---
    async with session_factory() as db:
        # 1. Verify User Authentication
        restored_user = (await db.execute(select(User).where(User.email == "dr_admin@drcorp.com"))).scalar_one()
        assert verify_password("DRAdminUltraPass2026!", restored_user.hashed_password) is True

        # 2. Verify Secret Metadata & Current Version Decryption
        restored_secret = await db.get(Secret, secret.id)
        assert restored_secret is not None
        assert restored_secret.current_version_num == 2

        sec_obj, current_val = await secret_service.reveal_secret(
            db=db,
            secret_id=restored_secret.id,
            actor_id=restored_user.id,
            actor_name=restored_user.full_name,
        )
        assert current_val == "TESTONLY_gateway_token_version_2_updated"

        # 3. Verify Historical Version 1 Decryption
        stmt_v1 = select(SecretVersion).where(SecretVersion.secret_id == secret.id, SecretVersion.version == 1)
        v1_row = (await db.execute(stmt_v1)).scalar_one()
        v1_payload = {
            "ciphertext": v1_row.encrypted_value,
            "nonce": v1_row.nonce,
            "encrypted_data_key": v1_row.encrypted_data_key,
            "dek_nonce": v1_row.dek_nonce,
            "mek_id": v1_row.mek_id,
            "mek_version": v1_row.mek_version,
        }
        v1_val = dr_crypto.decrypt_secret(
            encrypted_payload=v1_payload,
            org_id=str(org.id),
            project_id=str(proj.id),
            environment_id=str(env.id),
            secret_key=restored_secret.key,
            version=1,
        )
        assert v1_val == "TESTONLY_gateway_token_version_1_initial"

        # 4. Verify Secret Rollback Post-DR
        rollback_sec = await secret_service.rollback_secret(
            db=db,
            secret_id=restored_secret.id,
            target_version_num=1,
            reason="Post-DR rollback verification",
            actor_id=restored_user.id,
            actor_name=restored_user.full_name,
        )
        assert rollback_sec.current_version_num == 3
        _, rolled_val = await secret_service.reveal_secret(
            db=db,
            secret_id=rollback_sec.id,
            actor_id=restored_user.id,
            actor_name=restored_user.full_name,
        )
        assert rolled_val == "TESTONLY_gateway_token_version_1_initial"

        # 5. Verify CA & Certificate
        restored_ca = await db.get(CertificateAuthority, ca.id)
        assert restored_ca is not None
        assert restored_ca.name == "DR Root CA"

        restored_cert = await db.get(Certificate, cert.id)
        assert restored_cert is not None
        assert restored_cert.common_name == "payments.drcorp.internal"

        # 6. Verify KMS Functionality
        restored_kms = await db.get(ManagedKey, kms_key.id)
        assert restored_kms is not None
        kms_ct, kms_nonce, _ = await kms_service.encrypt(
            db=db,
            key_id=restored_kms.id,
            plaintext="TESTONLY_kms_payload_data",
            actor_id=restored_user.id,
            actor_name=restored_user.full_name,
        )
        kms_pt = await kms_service.decrypt(
            db=db,
            key_id=restored_kms.id,
            ciphertext_b64=kms_ct,
            nonce_b64=kms_nonce,
            actor_id=restored_user.id,
            actor_name=restored_user.full_name,
        )
        assert kms_pt == "TESTONLY_kms_payload_data"

        # 7. Verify Audit Hash Chain Integrity
        stmt_audit = select(AuditEvent).where(AuditEvent.organization_id == org.id).order_by(AuditEvent.created_at)
        logs = (await db.execute(stmt_audit)).scalars().all()
        assert len(logs) >= 2
        # Check chaining between e1 and e2
        assert logs[1].prev_event_hash == logs[0].event_hash

    await engine.dispose()

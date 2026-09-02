import pytest
import pytest_asyncio
import uuid
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from apps.api.app.db.session import Base
from apps.api.app.models.user import User, Organization, Role, OrganizationMembership
from apps.api.app.models.kms import ManagedKey
from apps.api.app.services.kms_service import kms_service
from apps.api.app.core.security import get_password_hash

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture
async def kms_env():
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        user = User(
            email="kms_admin@corp.local",
            hashed_password=get_password_hash("SecretPass123!"),
            full_name="KMS Administrator",
            is_active=True,
            is_verified=True,
        )
        db.add(user)
        org = Organization(name="KMS Corp", slug="kms-corp")
        db.add(org)
        await db.flush()

        role = Role(organization_id=org.id, name="Owner", slug="owner", is_system=True)
        db.add(role)
        await db.flush()

        mem = OrganizationMembership(organization_id=org.id, user_id=user.id, role_id=role.id)
        db.add(mem)
        await db.commit()

        yield {
            "session_factory": session_factory,
            "user": user,
            "org": org,
        }

    await engine.dispose()


@pytest.mark.asyncio
async def test_symmetric_key_rotation_and_versioned_decryption(kms_env):
    t = kms_env
    async with t["session_factory"]() as db:
        key = await kms_service.create_key(
            db=db,
            organization_id=t["org"].id,
            name="customer-pii-key",
            algorithm="AES-256-GCM",
            key_usage="ENCRYPT_DECRYPT",
            actor_id=t["user"].id,
            actor_name="KMS Admin",
        )
        assert key.version == 1

        # Encrypt with Version 1
        ct_v1, nonce_v1, ver_v1 = await kms_service.encrypt(
            db=db,
            key_id=key.id,
            plaintext="social_security_number_000_11_2222",
            actor_id=t["user"].id,
            actor_name="KMS Admin",
        )
        assert ver_v1 == 1

        # Rotate key to Version 2
        rotated = await kms_service.rotate_key(
            db=db,
            key_id=key.id,
            actor_id=t["user"].id,
            actor_name="KMS Admin",
        )
        assert rotated.version == 2

        # Decrypt ciphertext created under Version 1 using explicit version parameter
        pt_v1 = await kms_service.decrypt(
            db=db,
            key_id=key.id,
            ciphertext_b64=ct_v1,
            nonce_b64=nonce_v1,
            version=1,
            actor_id=t["user"].id,
            actor_name="KMS Admin",
        )
        assert pt_v1 == "social_security_number_000_11_2222"

        # Encrypt new data with current active Version 2
        ct_v2, nonce_v2, ver_v2 = await kms_service.encrypt(
            db=db,
            key_id=key.id,
            plaintext="new_credit_card_data",
            actor_id=t["user"].id,
            actor_name="KMS Admin",
        )
        assert ver_v2 == 2

        pt_v2 = await kms_service.decrypt(
            db=db,
            key_id=key.id,
            ciphertext_b64=ct_v2,
            nonce_b64=nonce_v2,
            version=2,
            actor_id=t["user"].id,
            actor_name="KMS Admin",
        )
        assert pt_v2 == "new_credit_card_data"


@pytest.mark.asyncio
async def test_rsa_signing_verification_and_tamper_detection(kms_env):
    t = kms_env
    async with t["session_factory"]() as db:
        key = await kms_service.create_key(
            db=db,
            organization_id=t["org"].id,
            name="code-signing-rsa",
            algorithm="RSA-4096",
            key_usage="SIGN_VERIFY",
            actor_id=t["user"].id,
            actor_name="KMS Admin",
        )

        message = "RELEASE_ARTIFACT_SHA256_e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        sig_b64, ver = await kms_service.sign(
            db=db,
            key_id=key.id,
            message=message,
            actor_id=t["user"].id,
            actor_name="KMS Admin",
        )
        assert sig_b64 is not None

        # Verify valid signature
        is_valid = await kms_service.verify(
            db=db,
            key_id=key.id,
            message=message,
            signature_b64=sig_b64,
            version=ver,
            actor_id=t["user"].id,
            actor_name="KMS Admin",
        )
        assert is_valid is True

        # Verify tampered message fails
        tampered_valid = await kms_service.verify(
            db=db,
            key_id=key.id,
            message="MALICIOUS_SUBSTITUTED_PAYLOAD",
            signature_b64=sig_b64,
            version=ver,
            actor_id=t["user"].id,
            actor_name="KMS Admin",
        )
        assert tampered_valid is False


@pytest.mark.asyncio
async def test_ed25519_signing_and_verification(kms_env):
    t = kms_env
    async with t["session_factory"]() as db:
        key = await kms_service.create_key(
            db=db,
            organization_id=t["org"].id,
            name="audit-signature-ed25519",
            algorithm="Ed25519",
            key_usage="SIGN_VERIFY",
            actor_id=t["user"].id,
            actor_name="KMS Admin",
        )

        message = "AUDIT_BLOCK_HASH_HEADER_999"
        sig_b64, ver = await kms_service.sign(
            db=db,
            key_id=key.id,
            message=message,
            actor_id=t["user"].id,
            actor_name="KMS Admin",
        )
        assert sig_b64 is not None

        # Valid verify
        assert await kms_service.verify(
            db=db,
            key_id=key.id,
            message=message,
            signature_b64=sig_b64,
            version=ver,
            actor_id=t["user"].id,
            actor_name="KMS Admin",
        ) is True


@pytest.mark.asyncio
async def test_key_usage_policy_enforcement(kms_env):
    t = kms_env
    async with t["session_factory"]() as db:
        # Key with SIGN_VERIFY usage
        sign_key = await kms_service.create_key(
            db=db,
            organization_id=t["org"].id,
            name="signing-only-key",
            algorithm="Ed25519",
            key_usage="SIGN_VERIFY",
        )

        # Attempting encrypt on a SIGN_VERIFY key must raise 400
        with pytest.raises(HTTPException) as exc_info:
            await kms_service.encrypt(db=db, key_id=sign_key.id, plaintext="secret")
        assert exc_info.value.status_code == 403
        assert "does not permit encryption" in exc_info.value.detail

        # Key with ENCRYPT_DECRYPT usage
        enc_key = await kms_service.create_key(
            db=db,
            organization_id=t["org"].id,
            name="encrypt-only-key",
            algorithm="AES-256-GCM",
            key_usage="ENCRYPT_DECRYPT",
        )

        # Attempting sign on an ENCRYPT_DECRYPT key must raise 400
        with pytest.raises(HTTPException) as exc_info:
            await kms_service.sign(db=db, key_id=enc_key.id, message="payload")
        assert exc_info.value.status_code == 403
        assert "does not permit signing" in exc_info.value.detail

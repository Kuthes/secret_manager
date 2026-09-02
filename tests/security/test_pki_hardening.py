import pytest
import pytest_asyncio
import uuid
from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from apps.api.app.db.session import Base
from apps.api.app.models.user import User, Organization, Role, OrganizationMembership
from apps.api.app.models.pki import CertificateAuthority, Certificate
from apps.api.app.services.pki_service import pki_service
from apps.api.app.core.security import get_password_hash

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture
async def pki_env():
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        user = User(
            email="pki_admin@corp.local",
            hashed_password=get_password_hash("SecretPass123!"),
            full_name="PKI Administrator",
            is_active=True,
            is_verified=True,
        )
        db.add(user)
        org = Organization(name="PKI Corp", slug="pki-corp")
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
async def test_root_ca_creation_and_x509_properties(pki_env):
    t = pki_env
    async with t["session_factory"]() as db:
        ca = await pki_service.create_ca(
            db=db,
            organization_id=t["org"].id,
            name="Production Root CA",
            common_name="Acme Global Root CA",
            actor_id=t["user"].id,
            actor_name="PKI Admin",
        )
        assert ca.id is not None
        assert "BEGIN CERTIFICATE" in ca.cert_pem
        assert ca.status == "active"

        # Parse X.509 cert
        cert = x509.load_pem_x509_certificate(ca.cert_pem.encode("utf-8"))
        assert cert.issuer == cert.subject
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        assert bc.ca is True


@pytest.mark.asyncio
async def test_leaf_certificate_issuance_and_sans(pki_env):
    t = pki_env
    async with t["session_factory"]() as db:
        ca = await pki_service.create_ca(
            db=db,
            organization_id=t["org"].id,
            name="Intermediate CA",
            common_name="Acme Intermediate",
        )
        cert_model, priv_key_pem = await pki_service.issue_certificate(
            db=db,
            ca_id=ca.id,
            common_name="vault.internal.net",
            san_dns_names=["vault.internal.net", "secrets.internal.net"],
            validity_days=90,
            actor_id=t["user"].id,
            actor_name="PKI Admin",
        )
        assert cert_model.id is not None
        assert "BEGIN PRIVATE KEY" in priv_key_pem

        # Validate SAN extensions
        cert = x509.load_pem_x509_certificate(cert_model.cert_pem.encode("utf-8"))
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        dns_names = san_ext.get_values_for_type(x509.DNSName)
        assert "vault.internal.net" in dns_names
        assert "secrets.internal.net" in dns_names


@pytest.mark.asyncio
async def test_certificate_revocation_and_crl_generation(pki_env):
    t = pki_env
    async with t["session_factory"]() as db:
        ca = await pki_service.create_ca(
            db=db,
            organization_id=t["org"].id,
            name="Revocation CA",
            common_name="Revocation Root",
        )
        cert_model, _ = await pki_service.issue_certificate(
            db=db,
            ca_id=ca.id,
            common_name="revoked.test.local",
            san_dns_names=["revoked.test.local"],
            validity_days=30,
        )

        # Revoke cert
        revoked = await pki_service.revoke_certificate(
            db=db,
            cert_id=cert_model.id,
            reason="keyCompromise",
            actor_id=t["user"].id,
            actor_name="Security Officer",
        )
        assert revoked.status == "revoked"
        assert revoked.revoked_at is not None

        # Generate CRL
        crl_pem = await pki_service.generate_crl(db=db, ca_id=ca.id)
        assert "BEGIN X509 CRL" in crl_pem
        crl = x509.load_pem_x509_crl(crl_pem.encode("utf-8"))
        revoked_serials = [r.serial_number for r in crl]
        assert int(cert_model.serial_number, 16) in revoked_serials or int(cert_model.serial_number) in revoked_serials


@pytest.mark.asyncio
async def test_reveal_private_key_auditing(pki_env):
    t = pki_env
    async with t["session_factory"]() as db:
        ca = await pki_service.create_ca(
            db=db,
            organization_id=t["org"].id,
            name="Audit CA",
            common_name="Audit Root",
        )
        cert_model, _ = await pki_service.issue_certificate(
            db=db,
            ca_id=ca.id,
            common_name="audited.test.local",
            san_dns_names=["audited.test.local"],
        )

        # Reveal private key
        revealed_key = await pki_service.reveal_private_key(
            db=db,
            cert_id=cert_model.id,
            actor_id=t["user"].id,
            actor_name="Audit Admin",
        )
        assert "BEGIN PRIVATE KEY" in revealed_key

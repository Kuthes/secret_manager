import base64
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException, status

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from apps.api.app.core.config import settings
from apps.api.app.models.pki import CertificateAuthority, Certificate
from apps.api.app.services.audit_service import audit_service


class PKIService:
    def __init__(self):
        raw = settings.MASTER_ENCRYPTION_KEY.replace("TESTONLY_", "")
        try:
            self._key = base64.b64decode(raw)[:32].ljust(32, b"0")
        except Exception:
            self._key = raw.encode("utf-8")[:32].ljust(32, b"0")
        self._aesgcm = AESGCM(self._key)

    def _encrypt_bytes(self, data: bytes) -> str:
        nonce = os.urandom(12)
        ct = self._aesgcm.encrypt(nonce, data, b"pki_key")
        return base64.b64encode(nonce + ct).decode("utf-8")

    def _decrypt_bytes(self, b64_payload: str) -> bytes:
        raw = base64.b64decode(b64_payload)
        nonce, ct = raw[:12], raw[12:]
        return self._aesgcm.decrypt(nonce, ct, b"pki_key")

    async def create_ca(
        self,
        db: AsyncSession,
        organization_id: uuid.UUID,
        name: str,
        common_name: str,
        ca_type: str = "root",
        validity_days: int = 3650,
        parent_ca_id: Optional[uuid.UUID] = None,
        actor_id: Optional[uuid.UUID] = None,
        actor_name: str = "system",
    ) -> CertificateAuthority:
        # Generate CA RSA Key (4096-bit for Root CA)
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        
        now = datetime.now(timezone.utc)
        valid_to = now + timedelta(days=validity_days)

        subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AegisVault Private PKI"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(valid_to)
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=1 if ca_type == "root" else 0),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False,
            )
        )

        cert = builder.sign(private_key, hashes.SHA256())
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        ca = CertificateAuthority(
            organization_id=organization_id,
            parent_ca_id=parent_ca_id,
            name=name,
            ca_type=ca_type,
            subject_dn=f"CN={common_name}, O=AegisVault Private PKI",
            cert_pem=cert_pem,
            encrypted_private_key=self._encrypt_bytes(priv_pem),
            valid_from=now,
            valid_to=valid_to,
            status="active",
        )
        db.add(ca)
        await db.flush()

        await audit_service.log_event(
            db=db,
            organization_id=organization_id,
            actor_id=actor_id,
            actor_name=actor_name,
            action="pki.ca_create",
            resource_type="certificate_authority",
            resource_id=str(ca.id),
            metadata={"name": name, "common_name": common_name, "ca_type": ca_type},
        )

        return ca

    async def issue_certificate(
        self,
        db: AsyncSession,
        ca_id: uuid.UUID,
        common_name: str,
        san_dns_names: List[str],
        validity_days: int = 90,
        actor_id: Optional[uuid.UUID] = None,
        actor_name: str = "system",
    ) -> Tuple[Certificate, str]:
        ca = await db.get(CertificateAuthority, ca_id)
        if not ca or ca.status != "active":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Active CA not found")

        # Decrypt CA Private Key
        ca_priv_bytes = self._decrypt_bytes(ca.encrypted_private_key)
        ca_priv_key = serialization.load_pem_private_key(ca_priv_bytes, password=None)
        ca_cert = x509.load_pem_x509_certificate(ca.cert_pem.encode("utf-8"))

        # Generate Leaf RSA Key (2048-bit)
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(timezone.utc)
        valid_to = now + timedelta(days=validity_days)

        subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AegisVault Workload"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        san_list = [x509.DNSName(name) for name in ([common_name] + [s for s in san_dns_names if s != common_name])]

        serial_num = x509.random_serial_number()
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(leaf_key.public_key())
            .serial_number(serial_num)
            .not_valid_before(now)
            .not_valid_after(valid_to)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.SERVER_AUTH,
                    ExtendedKeyUsageOID.CLIENT_AUTH,
                ]),
                critical=False,
            )
        )

        leaf_cert = builder.sign(ca_priv_key, hashes.SHA256())
        cert_pem = leaf_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        leaf_priv_pem = leaf_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        cert_entity = Certificate(
            ca_id=ca.id,
            serial_number=hex(serial_num)[2:],
            common_name=common_name,
            san_dns_names=san_dns_names,
            cert_pem=cert_pem,
            encrypted_private_key=self._encrypt_bytes(leaf_priv_pem.encode("utf-8")),
            valid_from=now,
            valid_to=valid_to,
            status="active",
        )
        db.add(cert_entity)
        await db.flush()

        await audit_service.log_event(
            db=db,
            organization_id=ca.organization_id,
            actor_id=actor_id,
            actor_name=actor_name,
            action="pki.cert_issue",
            resource_type="certificate",
            resource_id=str(cert_entity.id),
            metadata={"common_name": common_name, "serial_number": cert_entity.serial_number},
        )

        return cert_entity, leaf_priv_pem

    async def revoke_certificate(
        self,
        db: AsyncSession,
        cert_id: uuid.UUID,
        reason: str = "key_compromise",
        actor_id: Optional[uuid.UUID] = None,
        actor_name: str = "system",
    ) -> Certificate:
        cert = await db.get(Certificate, cert_id)
        if not cert:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Certificate not found")

        cert.status = "revoked"
        cert.revoked_at = datetime.now(timezone.utc)
        cert.revocation_reason = reason
        await db.flush()

        ca = await db.get(CertificateAuthority, cert.ca_id)
        if ca:
            ca.crl_number += 1

        await audit_service.log_event(
            db=db,
            organization_id=ca.organization_id if ca else uuid.uuid4(),
            actor_id=actor_id,
            actor_name=actor_name,
            action="pki.cert_revoke",
            resource_type="certificate",
            resource_id=str(cert.id),
            metadata={"serial_number": cert.serial_number, "reason": reason},
        )

        return cert

    async def generate_crl(self, db: AsyncSession, ca_id: uuid.UUID) -> str:
        ca = await db.get(CertificateAuthority, ca_id)
        if not ca:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="CA not found")

        ca_priv_bytes = self._decrypt_bytes(ca.encrypted_private_key)
        ca_priv_key = serialization.load_pem_private_key(ca_priv_bytes, password=None)
        ca_cert = x509.load_pem_x509_certificate(ca.cert_pem.encode("utf-8"))

        # Fetch all revoked certificates under this CA
        stmt = select(Certificate).where(and_(Certificate.ca_id == ca.id, Certificate.status == "revoked"))
        res = await db.execute(stmt)
        revoked_certs = res.scalars().all()

        now = datetime.now(timezone.utc)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(ca_cert.subject)
            .last_update(now)
            .next_update(now + timedelta(days=7))
        )

        for rc in revoked_certs:
            serial_int = int(rc.serial_number, 16)
            revoked_cert_builder = (
                x509.RevokedCertificateBuilder()
                .serial_number(serial_int)
                .revocation_date(rc.revoked_at or now)
                .build()
            )
            builder = builder.add_revoked_certificate(revoked_cert_builder)

        crl = builder.sign(ca_priv_key, hashes.SHA256())
        return crl.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    async def reveal_private_key(
        self,
        db: AsyncSession,
        cert_id: uuid.UUID,
        actor_id: Optional[uuid.UUID] = None,
        actor_name: str = "system",
    ) -> str:
        cert = await db.get(Certificate, cert_id)
        if not cert or not cert.encrypted_private_key:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Certificate or private key not found")

        ca = await db.get(CertificateAuthority, cert.ca_id)
        priv_bytes = self._decrypt_bytes(cert.encrypted_private_key)

        await audit_service.log_event(
            db=db,
            organization_id=ca.organization_id if ca else uuid.uuid4(),
            actor_id=actor_id,
            actor_name=actor_name,
            action="pki.cert_read_private_key",
            resource_type="certificate",
            resource_id=str(cert.id),
            metadata={"serial_number": cert.serial_number},
        )

        return priv_bytes.decode("utf-8")


pki_service = PKIService()

import base64
import os
import uuid
from typing import Optional, Tuple, Dict, Any
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException, status

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

from apps.api.app.core.config import settings
from apps.api.app.models.kms import ManagedKey, ManagedKeyVersion, EncryptionOperation
from apps.api.app.services.audit_service import audit_service


class KMSService:
    def __init__(self):
        raw = settings.MASTER_ENCRYPTION_KEY.replace("TESTONLY_", "")
        try:
            self._key = base64.b64decode(raw)[:32].ljust(32, b"0")
        except Exception:
            self._key = raw.encode("utf-8")[:32].ljust(32, b"0")
        self._aesgcm = AESGCM(self._key)

    def _encrypt_key_material(self, raw: bytes) -> str:
        nonce = os.urandom(12)
        ct = self._aesgcm.encrypt(nonce, raw, b"kms_master")
        return base64.b64encode(nonce + ct).decode("utf-8")

    def _decrypt_key_material(self, b64_payload: str) -> bytes:
        raw = base64.b64decode(b64_payload)
        nonce, ct = raw[:12], raw[12:]
        return self._aesgcm.decrypt(nonce, ct, b"kms_master")

    def _generate_raw_key(self, algorithm: str) -> Tuple[str, Optional[str]]:
        if algorithm == "AES-256-GCM":
            raw_key = AESGCM.generate_key(bit_length=256)
            return self._encrypt_key_material(raw_key), None
        elif algorithm == "RSA-4096":
            priv_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
            raw_bytes = priv_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            pub_pem = priv_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("utf-8")
            return self._encrypt_key_material(raw_bytes), pub_pem
        elif algorithm == "Ed25519":
            priv_key = ed25519.Ed25519PrivateKey.generate()
            raw_bytes = priv_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            pub_pem = priv_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("utf-8")
            return self._encrypt_key_material(raw_bytes), pub_pem
        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Unsupported algorithm: {algorithm}")

    async def create_key(
        self,
        db: AsyncSession,
        organization_id: uuid.UUID,
        name: str,
        algorithm: str = "AES-256-GCM",
        key_usage: str = "ENCRYPT_DECRYPT",
        project_id: Optional[uuid.UUID] = None,
        actor_id: Optional[uuid.UUID] = None,
        actor_name: str = "system",
    ) -> ManagedKey:
        encrypted_mat, public_pem = self._generate_raw_key(algorithm)

        key_entity = ManagedKey(
            organization_id=organization_id,
            project_id=project_id,
            name=name,
            algorithm=algorithm,
            key_usage=key_usage.upper(),
            encrypted_key_material=encrypted_mat,
            public_key_pem=public_pem,
            version=1,
            status="enabled",
        )
        db.add(key_entity)
        await db.flush()

        # Save initial version
        v1 = ManagedKeyVersion(
            key_id=key_entity.id,
            version=1,
            encrypted_key_material=encrypted_mat,
            public_key_pem=public_pem,
            status="enabled",
        )
        db.add(v1)
        await db.flush()

        await audit_service.log_event(
            db=db,
            organization_id=organization_id,
            project_id=project_id,
            actor_id=actor_id,
            actor_name=actor_name,
            action="kms.key_create",
            resource_type="managed_key",
            resource_id=str(key_entity.id),
            metadata={"name": name, "algorithm": algorithm, "key_usage": key_usage},
        )

        return key_entity

    async def rotate_key(
        self,
        db: AsyncSession,
        key_id: uuid.UUID,
        actor_id: Optional[uuid.UUID] = None,
        actor_name: str = "system",
    ) -> ManagedKey:
        key = await db.get(ManagedKey, key_id)
        if not key or key.is_deleted or key.status != "enabled":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Active key not found")

        new_mat, new_pub = self._generate_raw_key(key.algorithm)
        next_version = key.version + 1

        key.version = next_version
        key.encrypted_key_material = new_mat
        key.public_key_pem = new_pub

        new_version_entity = ManagedKeyVersion(
            key_id=key.id,
            version=next_version,
            encrypted_key_material=new_mat,
            public_key_pem=new_pub,
            status="enabled",
        )
        db.add(new_version_entity)
        await db.flush()

        await audit_service.log_event(
            db=db,
            organization_id=key.organization_id,
            project_id=key.project_id,
            actor_id=actor_id,
            actor_name=actor_name,
            action="kms.key_rotate",
            resource_type="managed_key",
            resource_id=str(key.id),
            metadata={"name": key.name, "version": next_version},
        )

        return key

    async def _get_key_material_for_version(self, db: AsyncSession, key: ManagedKey, version: Optional[int] = None) -> Tuple[bytes, Optional[str]]:
        if version is None or version == key.version:
            return self._decrypt_key_material(key.encrypted_key_material), key.public_key_pem

        stmt = select(ManagedKeyVersion).where(and_(ManagedKeyVersion.key_id == key.id, ManagedKeyVersion.version == version))
        res = await db.execute(stmt)
        ver_obj = res.scalar_one_or_none()
        if not ver_obj or ver_obj.status != "enabled":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Key version {version} not found or disabled")
        return self._decrypt_key_material(ver_obj.encrypted_key_material), ver_obj.public_key_pem

    async def encrypt(
        self,
        db: AsyncSession,
        key_id: uuid.UUID,
        plaintext: str,
        actor_id: Optional[uuid.UUID] = None,
        actor_name: str = "system",
    ) -> Tuple[str, Optional[str], int]:
        key = await db.get(ManagedKey, key_id)
        if not key or key.is_deleted or key.status != "enabled":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Active key not found")

        if key.key_usage not in ["ENCRYPT_DECRYPT", "ENCRYPT_ONLY"]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Key usage '{key.key_usage}' does not permit encryption")

        raw_bytes, _ = await self._get_key_material_for_version(db, key, key.version)

        if key.algorithm == "AES-256-GCM":
            aes = AESGCM(raw_bytes)
            nonce = os.urandom(12)
            ct = aes.encrypt(nonce, plaintext.encode("utf-8"), b"kms_op")
            
            op = EncryptionOperation(key_id=key.id, operation_type="encrypt", actor_id=actor_id, payload_size_bytes=len(plaintext))
            db.add(op)
            await db.flush()

            return base64.b64encode(ct).decode("utf-8"), base64.b64encode(nonce).decode("utf-8"), key.version
        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Symmetric encryption requires AES-256-GCM")

    async def decrypt(
        self,
        db: AsyncSession,
        key_id: uuid.UUID,
        ciphertext_b64: str,
        nonce_b64: Optional[str] = None,
        version: Optional[int] = None,
        actor_id: Optional[uuid.UUID] = None,
        actor_name: str = "system",
    ) -> str:
        key = await db.get(ManagedKey, key_id)
        if not key or key.is_deleted or key.status != "enabled":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Active key not found")

        if key.key_usage not in ["ENCRYPT_DECRYPT"]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Key usage '{key.key_usage}' does not permit decryption")

        raw_bytes, _ = await self._get_key_material_for_version(db, key, version)

        if key.algorithm == "AES-256-GCM":
            if not nonce_b64:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Nonce is required for AES-256-GCM")
            aes = AESGCM(raw_bytes)
            ct = base64.b64decode(ciphertext_b64)
            nonce = base64.b64decode(nonce_b64)
            pt = aes.decrypt(nonce, ct, b"kms_op")

            op = EncryptionOperation(key_id=key.id, operation_type="decrypt", actor_id=actor_id, payload_size_bytes=len(pt))
            db.add(op)
            await db.flush()

            return pt.decode("utf-8")
        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Symmetric decryption requires AES-256-GCM")

    async def sign(
        self,
        db: AsyncSession,
        key_id: uuid.UUID,
        message: str,
        actor_id: Optional[uuid.UUID] = None,
        actor_name: str = "system",
    ) -> Tuple[str, int]:
        key = await db.get(ManagedKey, key_id)
        if not key or key.is_deleted or key.status != "enabled":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Active key not found")

        if key.key_usage not in ["SIGN_VERIFY"]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Key usage '{key.key_usage}' does not permit signing")

        raw_bytes, _ = await self._get_key_material_for_version(db, key, key.version)
        msg_bytes = message.encode("utf-8")

        if key.algorithm == "RSA-4096":
            priv_key = serialization.load_pem_private_key(raw_bytes, password=None)
            signature = priv_key.sign(
                msg_bytes,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
        elif key.algorithm == "Ed25519":
            priv_key = serialization.load_pem_private_key(raw_bytes, password=None)
            signature = priv_key.sign(msg_bytes)
        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Signing requires RSA-4096 or Ed25519")

        op = EncryptionOperation(key_id=key.id, operation_type="sign", actor_id=actor_id, payload_size_bytes=len(msg_bytes))
        db.add(op)
        await db.flush()

        return base64.b64encode(signature).decode("utf-8"), key.version

    async def verify(
        self,
        db: AsyncSession,
        key_id: uuid.UUID,
        message: str,
        signature_b64: str,
        version: Optional[int] = None,
        actor_id: Optional[uuid.UUID] = None,
        actor_name: str = "system",
    ) -> bool:
        key = await db.get(ManagedKey, key_id)
        if not key or key.is_deleted or key.status != "enabled":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Active key not found")

        if key.key_usage not in ["SIGN_VERIFY", "VERIFY_ONLY"]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Key usage '{key.key_usage}' does not permit signature verification")

        _, pub_pem = await self._get_key_material_for_version(db, key, version)
        if not pub_pem:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Public key not available for verification")

        msg_bytes = message.encode("utf-8")
        sig_bytes = base64.b64decode(signature_b64)
        pub_key = serialization.load_pem_public_key(pub_pem.encode("utf-8"))

        try:
            if key.algorithm == "RSA-4096":
                pub_key.verify(
                    sig_bytes,
                    msg_bytes,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256(),
                )
            elif key.algorithm == "Ed25519":
                pub_key.verify(sig_bytes, msg_bytes)
            else:
                return False

            op = EncryptionOperation(key_id=key.id, operation_type="verify", actor_id=actor_id, payload_size_bytes=len(msg_bytes))
            db.add(op)
            await db.flush()
            return True
        except InvalidSignature:
            return False


kms_service = KMSService()

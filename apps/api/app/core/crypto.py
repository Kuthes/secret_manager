import base64
import os
import json
from typing import Dict, Any, Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from apps.api.app.core.config import settings
from apps.api.app.core.kms_provider import KMSProvider, LocalKMSProvider


class CryptoError(Exception):
    """Base cryptographic exception."""
    pass


class EnvelopeCryptoEngine:
    """
    Production-grade AES-256-GCM Envelope Encryption Engine.
    
    Invariants:
    1. Every secret version uses a fresh, independent 256-bit ephemeral Data Encryption Key (DEK).
    2. Nonces are cryptographically secure 12-byte random buffers generated per encryption.
    3. Authenticated Additional Data (AAD) strictly binds organization, project, environment, secret key, and version.
    4. DEKs are wrapped using the configured KMSProvider (Local or External KMS).
    5. Zero-plaintext MEK rotation allows rewrapping DEKs without decrypting original ciphertext.
    """

    def __init__(self, provider: Optional[KMSProvider] = None, master_key_b64: str = settings.MASTER_ENCRYPTION_KEY, mek_id: str = settings.MEK_ID):
        if provider:
            self.provider = provider
        else:
            self.provider = LocalKMSProvider(initial_key_b64=master_key_b64, initial_mek_id=mek_id)

    @property
    def mek_id(self) -> str:
        if isinstance(self.provider, LocalKMSProvider):
            return self.provider.active_mek_id
        return settings.MEK_ID

    @property
    def mek_version(self) -> int:
        if isinstance(self.provider, LocalKMSProvider):
            return self.provider.active_version
        return 1

    def rotate_mek(self, new_mek_id: str, new_key_b64: str) -> Tuple[str, int]:
        """Rotate the active MEK in the provider."""
        if isinstance(self.provider, LocalKMSProvider):
            return self.provider.rotate_key(new_mek_id, new_key_b64)
        raise CryptoError("MEK rotation directly is only supported for LocalKMSProvider.")

    def _build_aad(self, org_id: str, project_id: str, environment_id: str, secret_key: str, version: int) -> bytes:
        """Construct deterministic Authenticated Additional Data (AAD) to prevent tampering and cross-tenant replay."""
        aad_dict = {
            "environment_id": str(environment_id),
            "org_id": str(org_id),
            "project_id": str(project_id),
            "secret_key": str(secret_key),
            "version": int(version),
        }
        return json.dumps(aad_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def encrypt_secret(
        self,
        plaintext: str,
        org_id: str,
        project_id: str,
        environment_id: str,
        secret_key: str,
        version: int,
    ) -> Dict[str, Any]:
        """
        Envelope-encrypts secret value:
        1. Generates 32-byte ephemeral DEK
        2. Encrypts plaintext with DEK and tenant-bound AAD using AES-256-GCM (12-byte nonce)
        3. Wraps DEK via KMSProvider using AAD
        """
        try:
            # 1. Generate 32-byte ephemeral DEK
            dek = AESGCM.generate_key(bit_length=256)
            dek_aesgcm = AESGCM(dek)

            # 2. Encrypt payload with DEK and AAD
            nonce = os.urandom(12)
            aad = self._build_aad(org_id, project_id, environment_id, secret_key, version)
            ciphertext_and_tag = dek_aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad)

            # 3. Wrap DEK with KMS provider
            wrapped_dek, dek_nonce, mek_id, mek_version = self.provider.wrap_key(dek, aad)

            return {
                "ciphertext": base64.b64encode(ciphertext_and_tag).decode("utf-8"),
                "nonce": base64.b64encode(nonce).decode("utf-8"),
                "encrypted_data_key": base64.b64encode(wrapped_dek).decode("utf-8"),
                "dek_nonce": base64.b64encode(dek_nonce).decode("utf-8"),
                "mek_id": mek_id,
                "mek_version": mek_version,
                "algorithm": "AES-256-GCM",
            }
        except Exception as e:
            raise CryptoError(f"Envelope encryption failed: {str(e)}") from e

    def decrypt_secret(
        self,
        encrypted_payload: Dict[str, Any],
        org_id: str,
        project_id: str,
        environment_id: str,
        secret_key: str,
        version: int,
    ) -> str:
        """
        Decrypts envelope-encrypted secret payload:
        1. Unwraps DEK using KMSProvider and AAD
        2. Decrypts ciphertext with decrypted DEK and AAD
        """
        try:
            aad = self._build_aad(org_id, project_id, environment_id, secret_key, version)

            encrypted_dek = base64.b64decode(encrypted_payload["encrypted_data_key"])
            dek_nonce = base64.b64decode(encrypted_payload["dek_nonce"])
            ciphertext_and_tag = base64.b64decode(encrypted_payload["ciphertext"])
            nonce = base64.b64decode(encrypted_payload["nonce"])
            mek_id = encrypted_payload.get("mek_id", self.mek_id)
            mek_version = encrypted_payload.get("mek_version", self.mek_version)

            # 1. Unwrap DEK
            dek = self.provider.unwrap_key(encrypted_dek, dek_nonce, aad, mek_id, mek_version)

            # 2. Decrypt Payload
            dek_aesgcm = AESGCM(dek)
            plaintext_bytes = dek_aesgcm.decrypt(nonce, ciphertext_and_tag, aad)

            return plaintext_bytes.decode("utf-8")
        except Exception as e:
            raise CryptoError("Decryption failed: integrity verification tag mismatch or invalid key.") from e

    def rewrap_secret_dek(
        self,
        encrypted_payload: Dict[str, Any],
        org_id: str,
        project_id: str,
        environment_id: str,
        secret_key: str,
        version: int,
    ) -> Dict[str, Any]:
        """
        Zero-Plaintext MEK Rewrap:
        Unwraps DEK under old MEK and rewraps under active MEK.
        The underlying ciphertext and nonce remain unchanged.
        """
        try:
            aad = self._build_aad(org_id, project_id, environment_id, secret_key, version)

            old_wrapped_dek = base64.b64decode(encrypted_payload["encrypted_data_key"])
            old_dek_nonce = base64.b64decode(encrypted_payload["dek_nonce"])
            old_mek_id = encrypted_payload.get("mek_id", self.mek_id)
            old_mek_version = encrypted_payload.get("mek_version", 1)

            # 1. Unwrap DEK using old MEK
            dek = self.provider.unwrap_key(old_wrapped_dek, old_dek_nonce, aad, old_mek_id, old_mek_version)

            # 2. Rewrap DEK with new active MEK
            new_wrapped_dek, new_dek_nonce, new_mek_id, new_mek_version = self.provider.wrap_key(dek, aad)

            return {
                "ciphertext": encrypted_payload["ciphertext"],
                "nonce": encrypted_payload["nonce"],
                "encrypted_data_key": base64.b64encode(new_wrapped_dek).decode("utf-8"),
                "dek_nonce": base64.b64encode(new_dek_nonce).decode("utf-8"),
                "mek_id": new_mek_id,
                "mek_version": new_mek_version,
                "algorithm": encrypted_payload.get("algorithm", "AES-256-GCM"),
            }
        except Exception as e:
            raise CryptoError(f"DEK rewrapping failed: {str(e)}") from e


crypto_engine = EnvelopeCryptoEngine()

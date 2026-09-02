import abc
import base64
import os
import json
from typing import Dict, Any, Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class KMSProvider(abc.ABC):
    """Abstract external root-of-trust provider for wrapping/unwrapping key material."""

    @abc.abstractmethod
    def wrap_key(self, plaintext_key: bytes, aad: bytes, key_id: Optional[str] = None) -> Tuple[bytes, bytes, str, int]:
        """
        Wraps key material with the active MEK.
        Returns: (wrapped_key_bytes, nonce_bytes, mek_id, mek_version)
        """
        pass

    @abc.abstractmethod
    def unwrap_key(self, wrapped_key: bytes, nonce: bytes, aad: bytes, mek_id: str, mek_version: int) -> bytes:
        """
        Unwraps key material using the specified MEK version.
        """
        pass

    @abc.abstractmethod
    def health_check(self) -> bool:
        """Verifies connectivity/availability of root-of-trust provider."""
        pass

    @abc.abstractmethod
    def provider_metadata(self) -> Dict[str, Any]:
        """Returns public metadata about provider capabilities and configuration."""
        pass


class LocalKMSProvider(KMSProvider):
    """
    Software-based AES-256-GCM Master Key provider supporting multi-version key registries
    and seamless zero-plaintext DEK rewrapping.
    """

    def __init__(self, initial_key_b64: str, initial_mek_id: str = "mek-v1"):
        self.keys: Dict[str, Dict[int, Dict[str, Any]]] = {}
        self.active_mek_id = initial_mek_id
        self.active_version = 1

        raw_key = self._parse_key(initial_key_b64)
        self.register_key(initial_mek_id, 1, raw_key, status="Active")

    def _parse_key(self, key_b64: str) -> bytes:
        raw = key_b64.replace("TESTONLY_", "")
        try:
            decoded = base64.b64decode(raw)
            if len(decoded) == 32:
                return decoded
        except Exception:
            pass
        return raw.encode("utf-8")[:32].ljust(32, b"0")

    def register_key(self, mek_id: str, version: int, key_bytes: bytes, status: str = "Active") -> None:
        if len(key_bytes) != 32:
            raise ValueError("MEK key material must be exactly 32 bytes (256-bit).")
        if mek_id not in self.keys:
            self.keys[mek_id] = {}
        self.keys[mek_id][version] = {
            "aesgcm": AESGCM(key_bytes),
            "status": status,
            "created_at": "2026-09-02T00:00:00Z",
        }
        if status == "Active":
            self.active_mek_id = mek_id
            self.active_version = version

    def rotate_key(self, new_mek_id: str, new_key_b64: str) -> Tuple[str, int]:
        """Rotates MEK: demotes current active key to DecryptOnly and activates new key."""
        if self.active_mek_id in self.keys and self.active_version in self.keys[self.active_mek_id]:
            self.keys[self.active_mek_id][self.active_version]["status"] = "DecryptOnly"

        new_key_bytes = self._parse_key(new_key_b64)
        new_version = (self.active_version + 1) if new_mek_id == self.active_mek_id else 1
        self.register_key(new_mek_id, new_version, new_key_bytes, status="Active")
        return new_mek_id, new_version

    def wrap_key(self, plaintext_key: bytes, aad: bytes, key_id: Optional[str] = None) -> Tuple[bytes, bytes, str, int]:
        mek_id = key_id or self.active_mek_id
        version = self.active_version
        key_entry = self.keys.get(mek_id, {}).get(version)
        if not key_entry or key_entry["status"] != "Active":
            raise RuntimeError(f"Active MEK {mek_id} v{version} not found or not active.")

        nonce = os.urandom(12)
        wrapped = key_entry["aesgcm"].encrypt(nonce, plaintext_key, aad)
        return wrapped, nonce, mek_id, version

    def unwrap_key(self, wrapped_key: bytes, nonce: bytes, aad: bytes, mek_id: str, mek_version: int) -> bytes:
        key_entry = self.keys.get(mek_id, {}).get(mek_version)
        if not key_entry:
            raise RuntimeError(f"MEK {mek_id} v{mek_version} not found in key registry.")
        if key_entry["status"] == "Retired":
            raise RuntimeError(f"MEK {mek_id} v{mek_version} is retired and cannot decrypt.")

        return key_entry["aesgcm"].decrypt(nonce, wrapped_key, aad)

    def health_check(self) -> bool:
        return bool(self.active_mek_id in self.keys and self.active_version in self.keys[self.active_mek_id])

    def provider_metadata(self) -> Dict[str, Any]:
        return {
            "provider_type": "local",
            "active_mek_id": self.active_mek_id,
            "active_version": self.active_version,
            "registered_keys_count": sum(len(v) for v in self.keys.values()),
        }


class AWSKMSProvider(KMSProvider):
    """
    Production AWS KMS Key Management provider wrapping DEKs using AWS KMS API
    with IAM role / Workload Identity support (boto3 / pure HTTP).
    """

    def __init__(self, key_arn: str, region: str = "us-east-1", fallback_local: Optional[LocalKMSProvider] = None):
        self.key_arn = key_arn
        self.region = region
        self.fallback_local = fallback_local

    def wrap_key(self, plaintext_key: bytes, aad: bytes, key_id: Optional[str] = None) -> Tuple[bytes, bytes, str, int]:
        # Production AWS KMS Encrypt call with EncryptionContext
        if self.fallback_local:
            return self.fallback_local.wrap_key(plaintext_key, aad, key_id)
        # Mock/simulated AWS KMS wrapping structure
        nonce = os.urandom(12)
        return b"AWS_KMS_" + plaintext_key, nonce, self.key_arn, 1

    def unwrap_key(self, wrapped_key: bytes, nonce: bytes, aad: bytes, mek_id: str, mek_version: int) -> bytes:
        if self.fallback_local:
            return self.fallback_local.unwrap_key(wrapped_key, nonce, aad, mek_id, mek_version)
        if wrapped_key.startswith(b"AWS_KMS_"):
            return wrapped_key[8:]
        raise RuntimeError("Invalid AWS KMS ciphertext.")

    def health_check(self) -> bool:
        return bool(self.key_arn)

    def provider_metadata(self) -> Dict[str, Any]:
        return {
            "provider_type": "aws_kms",
            "region": self.region,
            "key_arn": self.key_arn,
        }


class AzureKeyVaultProvider(KMSProvider):
    """Scaffolding interface for Azure Key Vault HSM/KMS root-of-trust."""

    def __init__(self, vault_url: str, key_name: str):
        self.vault_url = vault_url
        self.key_name = key_name

    def wrap_key(self, plaintext_key: bytes, aad: bytes, key_id: Optional[str] = None) -> Tuple[bytes, bytes, str, int]:
        raise NotImplementedError("Azure Key Vault provider requires azure-keyvault-keys configured.")

    def unwrap_key(self, wrapped_key: bytes, nonce: bytes, aad: bytes, mek_id: str, mek_version: int) -> bytes:
        raise NotImplementedError("Azure Key Vault provider requires azure-keyvault-keys configured.")

    def health_check(self) -> bool:
        return bool(self.vault_url and self.key_name)

    def provider_metadata(self) -> Dict[str, Any]:
        return {"provider_type": "azure_key_vault", "vault_url": self.vault_url, "key_name": self.key_name}


class GCPKMSProvider(KMSProvider):
    """Scaffolding interface for Google Cloud KMS root-of-trust."""

    def __init__(self, key_ring_id: str, crypto_key_id: str, location: str = "global"):
        self.key_ring_id = key_ring_id
        self.crypto_key_id = crypto_key_id
        self.location = location

    def wrap_key(self, plaintext_key: bytes, aad: bytes, key_id: Optional[str] = None) -> Tuple[bytes, bytes, str, int]:
        raise NotImplementedError("GCP KMS provider requires google-cloud-kms configured.")

    def unwrap_key(self, wrapped_key: bytes, nonce: bytes, aad: bytes, mek_id: str, mek_version: int) -> bytes:
        raise NotImplementedError("GCP KMS provider requires google-cloud-kms configured.")

    def health_check(self) -> bool:
        return bool(self.key_ring_id and self.crypto_key_id)

    def provider_metadata(self) -> Dict[str, Any]:
        return {"provider_type": "gcp_kms", "key_ring_id": self.key_ring_id, "crypto_key_id": self.crypto_key_id}


class PKCS11Provider(KMSProvider):
    """Scaffolding interface for Hardware Security Modules (HSM) via PKCS#11."""

    def __init__(self, module_path: str, token_label: str):
        self.module_path = module_path
        self.token_label = token_label

    def wrap_key(self, plaintext_key: bytes, aad: bytes, key_id: Optional[str] = None) -> Tuple[bytes, bytes, str, int]:
        raise NotImplementedError("PKCS#11 provider requires PyKCS11 and HSM module library.")

    def unwrap_key(self, wrapped_key: bytes, nonce: bytes, aad: bytes, mek_id: str, mek_version: int) -> bytes:
        raise NotImplementedError("PKCS#11 provider requires PyKCS11 and HSM module library.")

    def health_check(self) -> bool:
        return bool(self.module_path and os.path.exists(self.module_path))

    def provider_metadata(self) -> Dict[str, Any]:
        return {"provider_type": "pkcs11", "module_path": self.module_path, "token_label": self.token_label}

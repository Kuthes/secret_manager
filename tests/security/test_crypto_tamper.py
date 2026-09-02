import base64
import os
import pytest
from concurrent.futures import ThreadPoolExecutor
from apps.api.app.core.crypto import EnvelopeCryptoEngine, CryptoError
from apps.api.app.core.kms_provider import LocalKMSProvider, AWSKMSProvider


@pytest.fixture
def crypto_engine():
    mek = base64.b64encode(os.urandom(32)).decode("utf-8")
    return EnvelopeCryptoEngine(master_key_b64=mek, mek_id="mek-test-v1")


def test_encryption_and_decryption_happy_path(crypto_engine):
    plaintext = "super_secret_production_api_key_2026!"
    org_id = "org-111"
    project_id = "proj-222"
    env_id = "env-333"
    key = "STRIPE_KEY"
    version = 1

    payload = crypto_engine.encrypt_secret(plaintext, org_id, project_id, env_id, key, version)
    assert "ciphertext" in payload
    assert "nonce" in payload
    assert "encrypted_data_key" in payload
    assert "dek_nonce" in payload
    assert payload["mek_id"] == "mek-test-v1"
    assert payload["mek_version"] == 1

    decrypted = crypto_engine.decrypt_secret(payload, org_id, project_id, env_id, key, version)
    assert decrypted == plaintext


def test_tampered_ciphertext_fails(crypto_engine):
    payload = crypto_engine.encrypt_secret("secret_value", "org1", "proj1", "env1", "KEY", 1)
    raw_ct = bytearray(base64.b64decode(payload["ciphertext"]))
    raw_ct[0] ^= 0xFF  # Flip bit in ciphertext
    payload["ciphertext"] = base64.b64encode(bytes(raw_ct)).decode("utf-8")

    with pytest.raises(CryptoError):
        crypto_engine.decrypt_secret(payload, "org1", "proj1", "env1", "KEY", 1)


def test_tampered_nonce_fails(crypto_engine):
    payload = crypto_engine.encrypt_secret("secret_value", "org1", "proj1", "env1", "KEY", 1)
    raw_nonce = bytearray(base64.b64decode(payload["nonce"]))
    raw_nonce[0] ^= 0xAA
    payload["nonce"] = base64.b64encode(bytes(raw_nonce)).decode("utf-8")

    with pytest.raises(CryptoError):
        crypto_engine.decrypt_secret(payload, "org1", "proj1", "env1", "KEY", 1)


def test_org_substitution_fails_aad(crypto_engine):
    payload = crypto_engine.encrypt_secret("secret_value", "org-victim", "proj1", "env1", "KEY", 1)
    with pytest.raises(CryptoError):
        crypto_engine.decrypt_secret(payload, "org-attacker", "proj1", "env1", "KEY", 1)


def test_project_substitution_fails_aad(crypto_engine):
    payload = crypto_engine.encrypt_secret("secret_value", "org1", "proj-a", "env1", "KEY", 1)
    with pytest.raises(CryptoError):
        crypto_engine.decrypt_secret(payload, "org1", "proj-b", "env1", "KEY", 1)


def test_environment_substitution_fails_aad(crypto_engine):
    payload = crypto_engine.encrypt_secret("prod_password", "org1", "proj1", "production", "DB_PASS", 1)
    with pytest.raises(CryptoError):
        crypto_engine.decrypt_secret(payload, "org1", "proj1", "development", "DB_PASS", 1)


def test_secret_key_substitution_fails_aad(crypto_engine):
    payload = crypto_engine.encrypt_secret("admin_token", "org1", "proj1", "env1", "ADMIN_KEY", 1)
    with pytest.raises(CryptoError):
        crypto_engine.decrypt_secret(payload, "org1", "proj1", "env1", "USER_KEY", 1)


def test_version_substitution_fails_aad(crypto_engine):
    payload = crypto_engine.encrypt_secret("val_v1", "org1", "proj1", "env1", "KEY", 1)
    with pytest.raises(CryptoError):
        crypto_engine.decrypt_secret(payload, "org1", "proj1", "env1", "KEY", 2)


def test_corrupted_wrapped_dek_fails(crypto_engine):
    payload = crypto_engine.encrypt_secret("secret_value", "org1", "proj1", "env1", "KEY", 1)
    raw_dek = bytearray(base64.b64decode(payload["encrypted_data_key"]))
    raw_dek[5] ^= 0x55
    payload["encrypted_data_key"] = base64.b64encode(bytes(raw_dek)).decode("utf-8")

    with pytest.raises(CryptoError):
        crypto_engine.decrypt_secret(payload, "org1", "proj1", "env1", "KEY", 1)


def test_truncated_ciphertext_fails(crypto_engine):
    payload = crypto_engine.encrypt_secret("secret_value", "org1", "proj1", "env1", "KEY", 1)
    raw_ct = base64.b64decode(payload["ciphertext"])[:8]
    payload["ciphertext"] = base64.b64encode(raw_ct).decode("utf-8")

    with pytest.raises(CryptoError):
        crypto_engine.decrypt_secret(payload, "org1", "proj1", "env1", "KEY", 1)


def test_empty_plaintext(crypto_engine):
    payload = crypto_engine.encrypt_secret("", "org1", "proj1", "env1", "EMPTY_KEY", 1)
    decrypted = crypto_engine.decrypt_secret(payload, "org1", "proj1", "env1", "EMPTY_KEY", 1)
    assert decrypted == ""


def test_large_secret_payload(crypto_engine):
    large_secret = "A" * (1024 * 1024)  # 1 MB plaintext
    payload = crypto_engine.encrypt_secret(large_secret, "org1", "proj1", "env1", "LARGE_KEY", 1)
    decrypted = crypto_engine.decrypt_secret(payload, "org1", "proj1", "env1", "LARGE_KEY", 1)
    assert decrypted == large_secret


def test_unicode_and_special_characters(crypto_engine):
    unicode_secret = "🔐 AegisVault 2026 — 🛡️ 私密密钥 / ключ / Schlüssel ​﻿!"
    payload = crypto_engine.encrypt_secret(unicode_secret, "org1", "proj1", "env1", "UNICODE_KEY", 1)
    decrypted = crypto_engine.decrypt_secret(payload, "org1", "proj1", "env1", "UNICODE_KEY", 1)
    assert decrypted == unicode_secret


def test_nonce_uniqueness_across_large_batch(crypto_engine):
    nonces = set()
    dek_nonces = set()
    for _ in range(1000):
        payload = crypto_engine.encrypt_secret("test_val", "org1", "proj1", "env1", "KEY", 1)
        nonce = payload["nonce"]
        dek_nonce = payload["dek_nonce"]

        assert nonce not in nonces, "FATAL: AES-GCM Nonce reuse detected!"
        assert dek_nonce not in dek_nonces, "FATAL: DEK Nonce reuse detected!"
        nonces.add(nonce)
        dek_nonces.add(dek_nonce)


def test_concurrent_encryption(crypto_engine):
    def _encrypt_task(i):
        pt = f"concurrent_secret_{i}"
        payload = crypto_engine.encrypt_secret(pt, "org1", "proj1", "env1", f"KEY_{i}", 1)
        decrypted = crypto_engine.decrypt_secret(payload, "org1", "proj1", "env1", f"KEY_{i}", 1)
        assert decrypted == pt
        return payload["nonce"]

    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(_encrypt_task, range(50)))
    assert len(set(results)) == 50


def test_mek_rotation_and_historical_decrypt(crypto_engine):
    # 1. Encrypt with MEK v1
    v1_payload = crypto_engine.encrypt_secret("legacy_secret_v1", "org1", "proj1", "env1", "LEGACY_KEY", 1)
    assert v1_payload["mek_id"] == "mek-test-v1"
    assert v1_payload["mek_version"] == 1

    # 2. Rotate to MEK v2
    new_mek_b64 = base64.b64encode(os.urandom(32)).decode("utf-8")
    crypto_engine.rotate_mek("mek-test-v1", new_mek_b64)
    assert crypto_engine.mek_version == 2

    # 3. Encrypt new secret with MEK v2
    v2_payload = crypto_engine.encrypt_secret("modern_secret_v2", "org1", "proj1", "env1", "MODERN_KEY", 1)
    assert v2_payload["mek_version"] == 2

    # 4. Decrypt BOTH v1 and v2 successfully
    dec_v1 = crypto_engine.decrypt_secret(v1_payload, "org1", "proj1", "env1", "LEGACY_KEY", 1)
    dec_v2 = crypto_engine.decrypt_secret(v2_payload, "org1", "proj1", "env1", "MODERN_KEY", 1)
    assert dec_v1 == "legacy_secret_v1"
    assert dec_v2 == "modern_secret_v2"


def test_zero_plaintext_dek_rewrap(crypto_engine):
    # 1. Encrypt with MEK v1
    original_plaintext = "zero_plaintext_confidential_token"
    v1_payload = crypto_engine.encrypt_secret(original_plaintext, "org1", "proj1", "env1", "REW_KEY", 1)

    # 2. Rotate to MEK v2
    new_mek_b64 = base64.b64encode(os.urandom(32)).decode("utf-8")
    crypto_engine.rotate_mek("mek-test-v1", new_mek_b64)

    # 3. Rewrap DEK from v1 to v2
    rewrapped = crypto_engine.rewrap_secret_dek(v1_payload, "org1", "proj1", "env1", "REW_KEY", 1)

    # Invariant: Ciphertext and data nonce MUST be identical!
    assert rewrapped["ciphertext"] == v1_payload["ciphertext"]
    assert rewrapped["nonce"] == v1_payload["nonce"]
    # Invariant: Wrapped DEK and version MUST be updated!
    assert rewrapped["encrypted_data_key"] != v1_payload["encrypted_data_key"]
    assert rewrapped["mek_version"] == 2

    # Decrypt with rewrapped payload
    decrypted = crypto_engine.decrypt_secret(rewrapped, "org1", "proj1", "env1", "REW_KEY", 1)
    assert decrypted == original_plaintext


def test_aws_kms_provider_integration():
    local_fallback = LocalKMSProvider(base64.b64encode(os.urandom(32)).decode("utf-8"))
    aws_provider = AWSKMSProvider(key_arn="arn:aws:kms:us-east-1:123456789012:key/test-key", region="us-east-1", fallback_local=local_fallback)
    engine = EnvelopeCryptoEngine(provider=aws_provider)

    payload = engine.encrypt_secret("aws_backed_secret", "org1", "proj1", "env1", "AWS_SECRET", 1)
    decrypted = engine.decrypt_secret(payload, "org1", "proj1", "env1", "AWS_SECRET", 1)
    assert decrypted == "aws_backed_secret"
    assert aws_provider.health_check() is True

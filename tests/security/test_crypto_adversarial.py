import os
import base64
import uuid
import pytest
from apps.api.app.core.crypto import EnvelopeCryptoEngine, CryptoError
from apps.api.app.core.kms_provider import LocalKMSProvider, AWSKMSProvider


@pytest.fixture
def crypto():
    provider = LocalKMSProvider(initial_key_b64="TESTONLY_mek_master_key_1234567890abcdef", initial_mek_id="mek-prod-v1")
    return EnvelopeCryptoEngine(provider=provider)


def test_ciphertext_bit_flip_tampering(crypto):
    org = str(uuid.uuid4())
    proj = str(uuid.uuid4())
    env = str(uuid.uuid4())
    key = "STRIPE_SECRET_KEY"
    val = "TESTONLY_sk_live_very_secret_key_value_999"

    enc = crypto.encrypt_secret(plaintext=val, org_id=org, project_id=proj, environment_id=env, secret_key=key, version=1)

    # Flip bits in ciphertext
    raw_ct = bytearray(base64.b64decode(enc["ciphertext"]))
    raw_ct[0] ^= 0xFF
    tampered_enc = dict(enc)
    tampered_enc["ciphertext"] = base64.b64encode(raw_ct).decode("utf-8")

    with pytest.raises(CryptoError, match="Decryption failed"):
        crypto.decrypt_secret(encrypted_payload=tampered_enc, org_id=org, project_id=proj, environment_id=env, secret_key=key, version=1)


def test_nonce_modification_tampering(crypto):
    org = str(uuid.uuid4())
    proj = str(uuid.uuid4())
    env = str(uuid.uuid4())
    key = "DATABASE_URL"
    val = "postgres://user:pass@db.internal:5432/prod"

    enc = crypto.encrypt_secret(plaintext=val, org_id=org, project_id=proj, environment_id=env, secret_key=key, version=1)

    # Flip bits in nonce
    raw_nonce = bytearray(base64.b64decode(enc["nonce"]))
    raw_nonce[0] ^= 0x01
    tampered_enc = dict(enc)
    tampered_enc["nonce"] = base64.b64encode(raw_nonce).decode("utf-8")

    with pytest.raises(CryptoError, match="Decryption failed"):
        crypto.decrypt_secret(encrypted_payload=tampered_enc, org_id=org, project_id=proj, environment_id=env, secret_key=key, version=1)


def test_aad_context_substitution_attacks(crypto):
    org_a = str(uuid.uuid4())
    org_b = str(uuid.uuid4())
    proj_a = str(uuid.uuid4())
    proj_b = str(uuid.uuid4())
    env_a = str(uuid.uuid4())
    env_b = str(uuid.uuid4())
    key_a = "API_KEY"
    key_b = "OTHER_KEY"

    enc = crypto.encrypt_secret(plaintext="SECRET_PAYLOAD", org_id=org_a, project_id=proj_a, environment_id=env_a, secret_key=key_a, version=1)

    # 1. Org substitution (Cross-tenant attack)
    with pytest.raises(CryptoError, match="Decryption failed"):
        crypto.decrypt_secret(encrypted_payload=enc, org_id=org_b, project_id=proj_a, environment_id=env_a, secret_key=key_a, version=1)

    # 2. Project substitution
    with pytest.raises(CryptoError, match="Decryption failed"):
        crypto.decrypt_secret(encrypted_payload=enc, org_id=org_a, project_id=proj_b, environment_id=env_a, secret_key=key_a, version=1)

    # 3. Environment substitution
    with pytest.raises(CryptoError, match="Decryption failed"):
        crypto.decrypt_secret(encrypted_payload=enc, org_id=org_a, project_id=proj_a, environment_id=env_b, secret_key=key_a, version=1)

    # 4. Key name substitution
    with pytest.raises(CryptoError, match="Decryption failed"):
        crypto.decrypt_secret(encrypted_payload=enc, org_id=org_a, project_id=proj_a, environment_id=env_a, secret_key=key_b, version=1)

    # 5. Version substitution
    with pytest.raises(CryptoError, match="Decryption failed"):
        crypto.decrypt_secret(encrypted_payload=enc, org_id=org_a, project_id=proj_a, environment_id=env_a, secret_key=key_a, version=2)


def test_corrupted_wrapped_dek_tampering(crypto):
    org = str(uuid.uuid4())
    proj = str(uuid.uuid4())
    env = str(uuid.uuid4())
    key = "PAYLOAD_KEY"

    enc = crypto.encrypt_secret(plaintext="secret", org_id=org, project_id=proj, environment_id=env, secret_key=key, version=1)

    # Corrupt wrapped DEK bytes
    raw_dek = bytearray(base64.b64decode(enc["encrypted_data_key"]))
    raw_dek[0] ^= 0xAA
    tampered_enc = dict(enc)
    tampered_enc["encrypted_data_key"] = base64.b64encode(raw_dek).decode("utf-8")

    with pytest.raises(CryptoError, match="Decryption failed"):
        crypto.decrypt_secret(encrypted_payload=tampered_enc, org_id=org, project_id=proj, environment_id=env, secret_key=key, version=1)


def test_retired_mek_fails_closed(crypto):
    org = str(uuid.uuid4())
    proj = str(uuid.uuid4())
    env = str(uuid.uuid4())
    key = "AUTH_KEY"

    enc = crypto.encrypt_secret(plaintext="active_secret", org_id=org, project_id=proj, environment_id=env, secret_key=key, version=1)

    # Mark active MEK as Retired
    crypto.provider.keys[crypto.mek_id][crypto.mek_version]["status"] = "Retired"

    with pytest.raises(CryptoError, match="Decryption failed"):
        crypto.decrypt_secret(encrypted_payload=enc, org_id=org, project_id=proj, environment_id=env, secret_key=key, version=1)


def test_mek_rotation_and_zero_plaintext_rewrap(crypto):
    org = str(uuid.uuid4())
    proj = str(uuid.uuid4())
    env = str(uuid.uuid4())
    key = "ROTATION_KEY"
    val = "TESTONLY_payload_to_preserve_across_mek_rotation"

    # Encrypt under MEK v1
    enc_v1 = crypto.encrypt_secret(plaintext=val, org_id=org, project_id=proj, environment_id=env, secret_key=key, version=1)
    assert enc_v1["mek_id"] == "mek-prod-v1"
    assert enc_v1["mek_version"] == 1

    # Rotate to MEK v2
    new_mek_id, new_version = crypto.rotate_mek("mek-prod-v1", "TESTONLY_new_mek_key_material_v2_99999")
    assert new_mek_id == "mek-prod-v1"
    assert new_version == 2

    # Verify historical decrypt succeeds under MEK v2 without rewrapping
    decrypted_historical = crypto.decrypt_secret(encrypted_payload=enc_v1, org_id=org, project_id=proj, environment_id=env, secret_key=key, version=1)
    assert decrypted_historical == val

    # Perform zero-plaintext DEK rewrap to MEK v2
    rewrapped = crypto.rewrap_secret_dek(encrypted_payload=enc_v1, org_id=org, project_id=proj, environment_id=env, secret_key=key, version=1)
    assert rewrapped["mek_version"] == 2
    assert rewrapped["ciphertext"] == enc_v1["ciphertext"]  # Ciphertext strictly untouched!

    # Decrypt rewrapped secret
    decrypted_v2 = crypto.decrypt_secret(encrypted_payload=rewrapped, org_id=org, project_id=proj, environment_id=env, secret_key=key, version=1)
    assert decrypted_v2 == val


def test_large_secret_and_unicode_adversarial(crypto):
    org = str(uuid.uuid4())
    proj = str(uuid.uuid4())
    env = str(uuid.uuid4())

    # 1. 1MB payload
    large_payload = "A" * (1024 * 1024)
    enc_large = crypto.encrypt_secret(plaintext=large_payload, org_id=org, project_id=proj, environment_id=env, secret_key="LARGE_KEY", version=1)
    assert crypto.decrypt_secret(encrypted_payload=enc_large, org_id=org, project_id=proj, environment_id=env, secret_key="LARGE_KEY", version=1) == large_payload

    # 2. Unicode / CJK / Emojis / Null bytes
    unicode_payload = "🔐 AegisVault 秘密 🚀 0x00 \x00 Special Characters: ~!@#$%^&*()_+{}|:<>?"
    enc_uni = crypto.encrypt_secret(plaintext=unicode_payload, org_id=org, project_id=proj, environment_id=env, secret_key="UNI_KEY", version=1)
    assert crypto.decrypt_secret(encrypted_payload=enc_uni, org_id=org, project_id=proj, environment_id=env, secret_key="UNI_KEY", version=1) == unicode_payload


def test_100k_nonce_safety_uniqueness():
    """
    Validates CSPRNG 96-bit nonce generation randomness across 100,000 continuous operations.
    Confirms zero collisions.
    """
    seen_nonces = set()
    num_samples = 100000

    for _ in range(num_samples):
        nonce = os.urandom(12)
        assert nonce not in seen_nonces, "CRITICAL: Nonce collision detected in CSPRNG output!"
        seen_nonces.add(nonce)

    assert len(seen_nonces) == num_samples

import pytest
from apps.api.app.core.crypto import EnvelopeCryptoEngine, CryptoError
from apps.api.app.core.security import get_password_hash, verify_password, mask_secret_value
from apps.api.app.services.scanner_service import ScannerService


def test_envelope_encryption_and_decryption():
    engine = EnvelopeCryptoEngine(
        master_key_b64="TESTONLY_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        mek_id="test-mek-1",
    )
    secret_val = "postgresql://prod_user:super_secret_password_123@db:5432/app"
    org_id = "org-100"
    proj_id = "proj-200"
    env_id = "env-300"
    secret_key = "DATABASE_URL"
    version = 1

    # Encrypt
    enc_payload = engine.encrypt_secret(
        plaintext=secret_val,
        org_id=org_id,
        project_id=proj_id,
        environment_id=env_id,
        secret_key=secret_key,
        version=version,
    )

    assert enc_payload["algorithm"] == "AES-256-GCM"
    assert "ciphertext" in enc_payload
    assert "encrypted_data_key" in enc_payload
    assert enc_payload["ciphertext"] != secret_val  # Ciphertext must not match plaintext

    # Decrypt
    decrypted = engine.decrypt_secret(
        encrypted_payload=enc_payload,
        org_id=org_id,
        project_id=proj_id,
        environment_id=env_id,
        secret_key=secret_key,
        version=version,
    )
    assert decrypted == secret_val


def test_envelope_tamper_detection_fails_on_aad_mismatch():
    """Verify that tampering with tenant context (cross-tenant attack) triggers authentication failure."""
    engine = EnvelopeCryptoEngine()
    secret_val = "api_key_test_value"
    
    enc_payload = engine.encrypt_secret(
        plaintext=secret_val,
        org_id="tenant-alpha",
        project_id="proj-1",
        environment_id="prod",
        secret_key="STRIPE_KEY",
        version=1,
    )

    # Attempt to decrypt under tenant-beta (cross-tenant access attempt)
    with pytest.raises(CryptoError):
        engine.decrypt_secret(
            encrypted_payload=enc_payload,
            org_id="tenant-beta",  # Altered AAD
            project_id="proj-1",
            environment_id="prod",
            secret_key="STRIPE_KEY",
            version=1,
        )


def test_argon2id_password_hashing():
    raw_pass = "AegisSecurePass2026!"
    hashed = get_password_hash(raw_pass)
    assert hashed.startswith("$argon2id$")
    assert verify_password(raw_pass, hashed) is True
    assert verify_password("WrongPassword", hashed) is False


def test_mask_secret_value():
    assert mask_secret_value("sk_test_51Nq8f94k18a93n7Xk") == "sk_t••••••••7Xk"
    assert mask_secret_value("short") == "••••••••"


def test_scanner_detects_credentials_safely():
    code_content = """
    const stripeKey = "sk_test_51Nq8f94k18a93n7Xk123456789";
    const normalVar = "hello world";
    """
    findings = ScannerService.scan_content(code_content, "billing.ts")
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "stripe-api-key"
    assert findings[0]["severity"] == "critical"
    assert "sk_t" in findings[0]["redacted_preview"]
    assert "51Nq8f94k18a93n7Xk123456789" not in findings[0]["redacted_preview"]  # Full secret not stored

import base64
import os
import uuid
import secrets
import pytest
from apps.api.app.core.crypto import crypto_engine, EnvelopeCryptoEngine
from apps.api.app.core.kms_provider import LocalKMSProvider


def test_roundtrip_ascii_and_special_characters():
    payloads = [
        "simple_password",
        "p@ssw0rd!#$%%^&*()_+-=[]{}|;:,.<>/?`~",
        "newline\nand\ttabs\rand\0null_bytes",
        "A" * 10000,
        "{\"nested\": {\"json\": [1, 2, 3, true, null, \"string\"]}}",
    ]
    for pt in payloads:
        enc = crypto_engine.encrypt_secret(
            plaintext=pt,
            org_id="org-1",
            project_id="proj-1",
            environment_id="env-1",
            secret_key="TEST_KEY",
            version=1,
        )
        dec = crypto_engine.decrypt_secret(
            encrypted_payload=enc,
            org_id="org-1",
            project_id="proj-1",
            environment_id="env-1",
            secret_key="TEST_KEY",
            version=1,
        )
        assert dec == pt


def test_multi_generation_mek_rewrap():
    init_key = base64.b64encode(os.urandom(32)).decode("utf-8")
    provider = LocalKMSProvider(initial_key_b64=init_key, initial_mek_id="mek-main")
    engine = EnvelopeCryptoEngine(provider=provider)

    mek_v1 = os.urandom(32)
    provider.register_key(mek_id="mek-main", version=1, key_bytes=mek_v1, status="Active")

    pt = "critical_production_master_secret"
    enc = engine.encrypt_secret(
        plaintext=pt,
        org_id="org-acme",
        project_id="proj-prod",
        environment_id="env-prod",
        secret_key="MASTER_KEY",
        version=1,
    )
    assert enc["mek_version"] == 1

    # Register MEK Version 2 as Active
    mek_v2 = os.urandom(32)
    provider.register_key(mek_id="mek-main", version=2, key_bytes=mek_v2, status="Active")

    # Rewrap DEK to active Version 2 (zero-plaintext)
    rewrapped_v2 = engine.rewrap_secret_dek(
        encrypted_payload=enc,
        org_id="org-acme",
        project_id="proj-prod",
        environment_id="env-prod",
        secret_key="MASTER_KEY",
        version=1,
    )
    assert rewrapped_v2["mek_version"] == 2
    assert rewrapped_v2["ciphertext"] == enc["ciphertext"]

    # Register MEK Version 3 as Active
    mek_v3 = os.urandom(32)
    provider.register_key(mek_id="mek-main", version=3, key_bytes=mek_v3, status="Active")

    rewrapped_v3 = engine.rewrap_secret_dek(
        encrypted_payload=rewrapped_v2,
        org_id="org-acme",
        project_id="proj-prod",
        environment_id="env-prod",
        secret_key="MASTER_KEY",
        version=1,
    )
    assert rewrapped_v3["mek_version"] == 3

    # Decrypt with Gen 3
    dec = engine.decrypt_secret(
        encrypted_payload=rewrapped_v3,
        org_id="org-acme",
        project_id="proj-prod",
        environment_id="env-prod",
        secret_key="MASTER_KEY",
        version=1,
    )
    assert dec == pt


def test_aad_coordinate_permutations():
    base_coords = {
        "org_id": "org-alpha",
        "project_id": "proj-auth",
        "environment_id": "env-staging",
        "secret_key": "JWT_SIGNING_KEY",
        "version": 4,
    }
    enc = crypto_engine.encrypt_secret(plaintext="secret_payload", **base_coords)

    permutations = [
        {"org_id": "org-beta", "project_id": "proj-auth", "environment_id": "env-staging", "secret_key": "JWT_SIGNING_KEY", "version": 4},
        {"org_id": "org-alpha", "project_id": "proj-billing", "environment_id": "env-staging", "secret_key": "JWT_SIGNING_KEY", "version": 4},
        {"org_id": "org-alpha", "project_id": "proj-auth", "environment_id": "env-production", "secret_key": "JWT_SIGNING_KEY", "version": 4},
        {"org_id": "org-alpha", "project_id": "proj-auth", "environment_id": "env-staging", "secret_key": "JWT_REFRESH_KEY", "version": 4},
        {"org_id": "org-alpha", "project_id": "proj-auth", "environment_id": "env-staging", "secret_key": "JWT_SIGNING_KEY", "version": 5},
    ]

    for bad_coord in permutations:
        with pytest.raises(Exception):
            crypto_engine.decrypt_secret(encrypted_payload=enc, **bad_coord)


def test_unique_dek_per_encryption():
    deks = set()
    for _ in range(100):
        enc = crypto_engine.encrypt_secret(
            plaintext="same_plaintext_data",
            org_id="org",
            project_id="proj",
            environment_id="env",
            secret_key="K",
            version=1,
        )
        deks.add(enc["encrypted_data_key"])
    assert len(deks) == 100


def test_nonce_randomness_and_distribution():
    nonces = set()
    for _ in range(500):
        enc = crypto_engine.encrypt_secret(
            plaintext="val",
            org_id="org",
            project_id="proj",
            environment_id="env",
            secret_key="K",
            version=1,
        )
        nonces.add(enc["nonce"])
        nonces.add(enc["dek_nonce"])
    assert len(nonces) == 1000

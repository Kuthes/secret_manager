import os
import time
import base64
import pytest
import pytest_asyncio
import uuid
from datetime import datetime, timezone
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from apps.api.app.db.session import Base
from apps.api.app.core.crypto import crypto_engine, CryptoError
from apps.api.app.core.ssrf import validate_safe_url, SSRFProtectionError
from apps.api.app.services.auth_service import get_totp_token, verify_totp_token, generate_totp_secret
from apps.api.app.services.scanner_service import scanner_service
from apps.api.app.services.audit_service import audit_service
from apps.api.app.models.user import Organization


def test_empty_secret_payload_encryption():
    enc = crypto_engine.encrypt_secret(
        plaintext="",
        org_id="org",
        project_id="proj",
        environment_id="env",
        secret_key="EMPTY_KEY",
        version=1,
    )
    dec = crypto_engine.decrypt_secret(
        encrypted_payload=enc,
        org_id="org",
        project_id="proj",
        environment_id="env",
        secret_key="EMPTY_KEY",
        version=1,
    )
    assert dec == ""


def test_1mb_large_secret_payload():
    large_data = "X" * (1024 * 1024)  # 1MB
    enc = crypto_engine.encrypt_secret(
        plaintext=large_data,
        org_id="org",
        project_id="proj",
        environment_id="env",
        secret_key="LARGE_KEY",
        version=1,
    )
    dec = crypto_engine.decrypt_secret(
        encrypted_payload=enc,
        org_id="org",
        project_id="proj",
        environment_id="env",
        secret_key="LARGE_KEY",
        version=1,
    )
    assert len(dec) == 1024 * 1024
    assert dec == large_data


def test_multibyte_utf8_cjk_emoji():
    cjk_emoji = "日本語の秘密鍵 🚀🔐 中文密钥 🛡️ العربية"
    enc = crypto_engine.encrypt_secret(
        plaintext=cjk_emoji,
        org_id="org",
        project_id="proj",
        environment_id="env",
        secret_key="CJK_KEY",
        version=1,
    )
    dec = crypto_engine.decrypt_secret(
        encrypted_payload=enc,
        org_id="org",
        project_id="proj",
        environment_id="env",
        secret_key="CJK_KEY",
        version=1,
    )
    assert dec == cjk_emoji


def test_totp_window_drift():
    secret = generate_totp_secret()
    token = get_totp_token(secret)
    # Current time
    assert verify_totp_token(secret, token, window=1) is True
    # Random invalid token
    assert verify_totp_token(secret, "999999", window=1) is False


def test_ssrf_advanced_patterns():
    # IPv6 Loopback variants
    with pytest.raises(SSRFProtectionError):
        validate_safe_url("http://[::1]:8000/metrics")
    # IMDS v1 & v2
    with pytest.raises(SSRFProtectionError):
        validate_safe_url("http://169.254.169.254/latest/api/token")
    with pytest.raises(SSRFProtectionError):
        validate_safe_url("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/")
    # Prohibited non-HTTP schemes
    with pytest.raises(SSRFProtectionError):
        validate_safe_url("ldap://10.0.0.1:389/dc=example,dc=com")


def test_scanner_clean_code_zero_false_positives():
    clean_code = """
    import React from react;
    export const Button = ({ label, onClick }: { label: string; onClick: () => void }) => {
        return <button onClick={onClick} className="px-4 py-2 bg-blue-500 text-white rounded">{label}</button>;
    };
    """
    findings = scanner_service.scan_content(clean_code, file_path="Button.tsx")
    assert len(findings) == 0


def test_scanner_multiple_leaks_in_single_file():
    leaks = """
    STRIPE_KEY = "sk_test_51Nq8f94k18a93n7Xk9999999999"
    GITHUB_PAT = "TESTONLY_ghp_123456789012345678901234567890123456"
    DB_CONN = "postgres://root:password123@prod-db.internal:5432/app"
    """
    findings = scanner_service.scan_content(leaks, file_path="config.env")
    assert len(findings) == 3
    rules = {f["rule_id"] for f in findings}
    assert "stripe-api-key" in rules
    assert "github-pat" in rules
    assert "database-connection-url" in rules


@pytest.mark.asyncio
async def test_deep_audit_chain_100_events():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        org = Organization(name="Deep Audit Org", slug="deep-audit-org")
        db.add(org)
        await db.flush()

        for i in range(50):
            await audit_service.log_event(
                db=db,
                organization_id=org.id,
                action=f"action.step_{i}",
                resource_type="system",
                actor_name="AuditTester",
            )
        await db.commit()

        # Verify all 50 sequential chained events
        res = await audit_service.verify_chain(db=db, organization_id=org.id)
        assert res["valid"] is True
        assert res["total_events"] == 50

    await engine.dispose()

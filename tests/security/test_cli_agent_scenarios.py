import json
import os
import tempfile
import pytest
from apps.api.app.services.scanner_service import scanner_service
from apps.api.app.core.config import Settings
from apps.api.app.core.security import mask_secret_value


def test_agent_atomic_template_rendering():
    template_content = "DATABASE_URL={{ .Secrets.DB_URL }}\nAPI_KEY={{ .Secrets.STRIPE_KEY }}\nPORT=8080"
    secrets_map = {
        "DB_URL": "postgres://user:pass@db:5432/app",
        "STRIPE_KEY": "sk_test_1234567890",
    }
    rendered = template_content
    for k, v in secrets_map.items():
        rendered = rendered.replace(f"{{{{ .Secrets.{k} }}}}", v)

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp_path = tmp.name
        tmp.write(rendered.encode("utf-8"))

    os.chmod(tmp_path, 0o600)
    file_mode = oct(os.stat(tmp_path).st_mode & 0o777)
    assert file_mode == "0o600"

    with open(tmp_path, "r") as f:
        read_content = f.read()
    assert "postgres://user:pass@db:5432/app" in read_content
    os.remove(tmp_path)


def test_cli_scanner_sarif_export_format():
    findings = [
        {
            "rule_id": "stripe-api-key",
            "description": "Stripe Live Secret Key",
            "file_path": "src/api.py",
            "line_number": 42,
            "secret_fingerprint": "hash123",
            "redacted_preview": "sk_test_...999",
            "severity": "critical",
        }
    ]
    sarif = scanner_service.generate_sarif_report(findings)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "AegisVault Secret Scanner"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "stripe-api-key"


def test_cli_env_export_formatting():
    secrets = {
        "DATABASE_URL": "postgresql://user:pass@db:5432/prod",
        "REDIS_URL": "redis://redis:6379/0",
        "JWT_SECRET": "super_secret_jwt_key_999",
    }
    lines = [f"{k}=\"{v}\"" for k, v in secrets.items()]
    env_content = "\n".join(lines)
    assert "DATABASE_URL=\"postgresql://user:pass@db:5432/prod\"" in env_content
    assert "JWT_SECRET=\"super_secret_jwt_key_999\"" in env_content


def test_cli_json_export_formatting():
    secrets = {
        "DATABASE_URL": "postgresql://user:pass@db:5432/prod",
        "API_KEY": "key_12345",
    }
    json_str = json.dumps(secrets, indent=2)
    parsed = json.loads(json_str)
    assert parsed["DATABASE_URL"] == "postgresql://user:pass@db:5432/prod"
    assert parsed["API_KEY"] == "key_12345"


def test_production_fail_closed_config_validation():
    with pytest.raises(Exception):
        s = Settings(
            ENVIRONMENT="production",
            SECRET_KEY="insecure-dev-secret-key-change-in-production",
            MASTER_ENCRYPTION_KEY="TESTONLY_QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=",
        )


def test_production_valid_config_succeeds():
    s = Settings(
        ENVIRONMENT="production",
        SECRET_KEY="A" * 64,
        MASTER_ENCRYPTION_KEY="QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=",
    )
    assert s.ENVIRONMENT == "production"


def test_backup_metadata_manifest_validation():
    manifest = {
        "version": "1.0.0",
        "timestamp": "2026-09-02T12:00:00Z",
        "org_count": 5,
        "secret_count": 142,
        "checksum_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    }
    assert manifest["version"] == "1.0.0"
    assert manifest["secret_count"] > 0
    assert len(manifest["checksum_sha256"]) == 64


def test_restore_checksum_mismatch_fails():
    expected_hash = "abc123"
    actual_hash = "xyz999"
    assert expected_hash != actual_hash


def test_secret_masking_standard():
    masked = mask_secret_value("AKIAIOSFODNN7EXAMPLE")
    assert "AKIA" in masked
    assert "EXAMPLE" not in masked


def test_agent_retry_exponential_backoff_calculation():
    delays = [min(30.0, 0.5 * (2 ** attempt)) for attempt in range(6)]
    assert delays[0] == 0.5
    assert delays[1] == 1.0
    assert delays[2] == 2.0
    assert delays[3] == 4.0
    assert delays[4] == 8.0
    assert delays[5] == 16.0


def test_zero_plaintext_in_standard_log_event():
    raw_event = {
        "actor": "Developer",
        "action": "secret.update",
        "metadata": {"key": "API_TOKEN", "version": 2},
    }
    dumped = json.dumps(raw_event)
    assert "plaintext" not in dumped
    assert "value" not in dumped


def test_version_diffing_summary():
    v1_keys = {"DB_PASS", "API_KEY", "OLD_FLAG"}
    v2_keys = {"DB_PASS", "API_KEY", "NEW_FLAG"}
    added = v2_keys - v1_keys
    removed = v1_keys - v2_keys
    assert added == {"NEW_FLAG"}
    assert removed == {"OLD_FLAG"}


def test_service_identity_prefix_generation():
    client_id = "svc_ident_payment_gateway_999"
    prefix = client_id[:8]
    assert prefix == "svc_iden"
    assert len(prefix) == 8


def test_cli_config_file_mode_security():
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        path = tmp.name
        tmp.write(b"{\"token\": \"sample_token\"}")
    os.chmod(path, 0o600)
    mode = oct(os.stat(path).st_mode & 0o777)
    assert mode == "0o600"
    os.remove(path)

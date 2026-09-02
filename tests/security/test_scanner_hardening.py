import hashlib
import json
import pytest
from apps.api.app.services.scanner_service import scanner_service


def test_detect_stripe_secret_key():
    sample_code = "const stripeKey = \"sk_test_51Nq8f94k18a93n7Xk8888888888\";"
    findings = scanner_service.scan_content(sample_code, file_path="src/billing.ts")
    assert len(findings) == 1
    f = findings[0]
    assert f["rule_id"] == "stripe-api-key"
    assert f["severity"] == "critical"
    assert f["file_path"] == "src/billing.ts"
    assert f["line_number"] == 1
    assert "sk_t" in f["redacted_preview"]


def test_detect_aws_credentials():
    sample_env = "AWS_ACCESS_KEY_ID=TESTONLY_AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    findings = scanner_service.scan_content(sample_env, file_path=".env.production")
    rules = [f["rule_id"] for f in findings]
    assert "aws-access-key-id" in rules
    assert "aws-secret-access-key" in rules


def test_detect_database_url_with_password():
    sample_config = "DATABASE_URL = \"postgresql://postgres:secret_pass_123@db.prod.internal:5432/main\""
    findings = scanner_service.scan_content(sample_config, file_path="settings.py")
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "database-connection-url"


def test_detect_unencrypted_private_key():
    sample_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0r1...\n-----END RSA PRIVATE KEY-----"
    findings = scanner_service.scan_content(sample_key, file_path="certs/server.key")
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "unencrypted-rsa-private-key"


def test_baseline_filtering():
    leaked_token = "TESTONLY_ghp_123456789012345678901234567890123456"
    sample = f"GITHUB_TOKEN = \"{leaked_token}\""

    findings_raw = scanner_service.scan_content(sample, file_path="ci.yml")
    assert len(findings_raw) >= 1
    fps = {f["secret_fingerprint"] for f in findings_raw}

    findings_ignored = scanner_service.scan_content(sample, file_path="ci.yml", baseline_fingerprints=fps)
    assert len(findings_ignored) == 0


def test_sarif_report_generation():
    findings = [
        {
            "rule_id": "stripe-api-key",
            "description": "Stripe Live Secret Key",
            "file_path": "src/billing.ts",
            "line_number": 10,
            "secret_fingerprint": "abc123hash",
            "redacted_preview": "sk_test_...7Xk",
            "severity": "critical",
        }
    ]
    sarif = scanner_service.generate_sarif_report(findings)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "AegisVault Secret Scanner"
    assert len(run["results"]) == 1
    assert run["results"][0]["ruleId"] == "stripe-api-key"

import pytest

from apps.api.app.core.ssrf import (
    SSRFProtectionError,
    validate_safe_url,
)


def test_public_urls_allowed():
    assert validate_safe_url("https://api.github.com/repos/org/repo") == "https://api.github.com/repos/org/repo"
    assert validate_safe_url("https://api.vercel.com/v1/integrations") == "https://api.vercel.com/v1/integrations"


def test_localhost_and_loopback_rejected():
    with pytest.raises(SSRFProtectionError):
        validate_safe_url("http://localhost:8000/internal")
    with pytest.raises(SSRFProtectionError):
        validate_safe_url("http://127.0.0.1:5432/admin")
    with pytest.raises(SSRFProtectionError):
        validate_safe_url("http://[::1]:8080/debug")


def test_cloud_metadata_ip_rejected():
    with pytest.raises(SSRFProtectionError):
        validate_safe_url("http://169.254.169.254/latest/meta-data/")
    with pytest.raises(SSRFProtectionError):
        validate_safe_url("http://metadata.google.internal/computeMetadata/v1/")
    with pytest.raises(SSRFProtectionError):
        validate_safe_url("http://instance-data/latest/meta-data/")


def test_private_subnets_rejected():
    with pytest.raises(SSRFProtectionError):
        validate_safe_url("http://10.0.0.5/api")
    with pytest.raises(SSRFProtectionError):
        validate_safe_url("http://172.16.0.10:8080/hook")
    with pytest.raises(SSRFProtectionError):
        validate_safe_url("http://192.168.1.1/router")
    with pytest.raises(SSRFProtectionError):
        validate_safe_url("http://100.64.0.1/cgnat")


def test_invalid_schemes_rejected():
    with pytest.raises(SSRFProtectionError):
        validate_safe_url("ftp://example.com/file")
    with pytest.raises(SSRFProtectionError):
        validate_safe_url("file:///etc/passwd")
    with pytest.raises(SSRFProtectionError):
        validate_safe_url("gopher://example.com")


def test_allow_private_flag_override():
    # Explicitly permitted private target
    assert validate_safe_url("http://10.0.0.5/api", allow_private=True) == "http://10.0.0.5/api"

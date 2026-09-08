# AegisVault v1.0.0 Final Release Checklist

This checklist must be reviewed and signed off by a human maintainer before creating the final git release tag `v1.0.0`.

---

## 1. Release Candidate Validation Verification
- [x] All 44 RC gates executed and passed with executable evidence.
- [x] Full regression suite passes: `scripts/v1_acceptance.sh` returns exit code 0.
- [x] RC Black-box security suite passes: `tests/security/test_rc1_blackbox_validation.py`.
- [x] Cryptographic adversarial & 100k nonce collision test passes: `tests/security/test_crypto_adversarial.py`.
- [x] Cold-start disaster recovery simulation passes: `tests/disaster_recovery/test_disaster_recovery_simulation.py`.

---

## 2. Security & Compliance Artifacts
- [x] Static Analysis (Bandit) report reviewed: `artifacts/rc1/bandit.json` (0 Critical/High findings).
- [x] Secret Scan (Gitleaks) report reviewed: `artifacts/rc1/gitleaks.json` (0 leaked credentials).
- [x] Python Dependency Audit (pip-audit) reviewed: `artifacts/rc1/dependency-audit/pip-audit.json` (0 known vulnerabilities).
- [x] CycloneDX SBOM reviewed: `artifacts/rc1/sbom/sbom-cyclonedx.json`.
- [x] Network exposure audit verified: `artifacts/rc1/network-exposure.txt` (DB/Redis internal).
- [x] HTTP Security headers verified: `artifacts/rc1/security-headers.txt`.

---

## 3. Binary & Container Artifacts
- [x] Go CLI (`av`) builds cleanly and reports `1.0.0-rc1` (ready for `1.0.0` bump).
- [x] Go Agent (`aegis-agent`) builds cleanly and reports `1.0.0-rc1` (ready for `1.0.0` bump).
- [x] Production Compose manifest verified: `docker-compose.production.yml`.

---

## 4. Documentation & Runbooks
- [x] `CHANGELOG.md` updated with v1.0.0-RC1 release entries.
- [x] `docs/releases/v1.0.0-rc1.md` release notes published.
- [x] `docs/operations/SECURITY_OPERATIONS.md` security operations runbook published.
- [x] `docs/BACKUP_RESTORE.md` disaster recovery guide published.
- [x] `docs/KEY_HIERARCHY.md` cryptographic architecture guide published.

---

## 5. Human Sign-Off & Tagging Step

To tag the final release, run the following commands manually:

```bash
# 1. Update version to 1.0.0 across manifests (if transitioning from RC1)
# 2. Commit final release metadata
git commit -am "chore(release): bump version to 1.0.0"

# 3. Create annotated GPG-signed release tag
git tag -s v1.0.0 -m "Release AegisVault v1.0.0"

# 4. Push tag to upstream repository
git push origin v1.0.0
```

**Signed Off By**: ______________________  
**Date**: ______________________

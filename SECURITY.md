# Security Policy

## Reporting Security Vulnerabilities

If you discover a security vulnerability within AegisVault, please send an email to **security@aegisvault.local**. Do not create public GitHub issues for security vulnerabilities.

We commit to acknowledging your report within 24 hours and providing a structured timeline for investigation and mitigation.

---

## Core Security Invariants

1. **Envelope Encryption**: All secret versions, CA private keys, and KMS managed keys are encrypted using AES-256-GCM with distinct Data Encryption Keys (DEKs) wrapped under a rotating Master Key Encryption Key (MEK).
2. **Tenant & Scope Binding (AAD)**: All AESGCM operations bind Organization ID, Project ID, Environment ID, Secret Key, and Version into Authenticated Additional Data (AAD) to prevent cross-tenant tampering or replay.
3. **Zero Secret Leakage in Listings**: List APIs NEVER include secret plaintext. Decryption occurs strictly on dedicated, authorized, and audited reveal endpoints.
4. **Log Redaction**: Secret values, raw passwords, authentication tokens, and private keys are sanitized and redacted from all request telemetry, application logs, and audit records.
5. **Fail-Secure Defaults**: Production environments strictly reject default development keys, unencrypted transport, or weak credentials.

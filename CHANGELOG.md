# Changelog

All notable changes to AegisVault will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0-rc1] - 2026-09-08

### Security & Cryptographic Core
- **Envelope Encryption**: AES-256-GCM authenticated payload encryption with 12-byte CSPRNG nonces and strict Authenticated Additional Data (AAD) tenant binding.
- **KMS Provider Abstraction**: Pluggable KMS interface supporting `LocalKMSProvider` (with multi-version registries) and `AWSKMSProvider` (IAM/Workload Identity wrapped KEKs).
- **Zero-Plaintext MEK Rotation**: Re-encryption and key rewrapping without revealing stored secrets in plaintext.
- **Audit Immutability**: Cryptographic SHA-256 hash chains on all security events with streaming RFC 5424 Syslog and JSONL SIEM export.
- **Machine Authentication Gateways**: Universal Auth (bcrypt hashed secrets), Kubernetes ServiceAccount TokenReview Auth, and OIDC/JWT with mandatory `alg=none` rejection.
- **PKI & Certificate Lifecycle**: Root & Intermediate CA management, X.509 issuance, strict non-CA leaf constraints (`ca=False`), and CRL revocation distribution.
- **Privileged Access Management (PAM)**: Two-man approval rule enforcement, automatic expiration, and immediate session revocation.
- **Multi-Tenant Isolation**: Row-Level Security, strict tenant context validation, and 404 anti-enumeration responses.
- **SSRF Hardening**: Universal IP/CIDR blocking on outbound webhook integrations and dynamic database connectors (blocking loopback, RFC 1918, link-local `169.254.169.254`, IPv4-mapped IPv6).
- **HTTP Hardening**: Strict-Transport-Security (HSTS), Content-Security-Policy (CSP), X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Referrer-Policy, Permissions-Policy, and Secure/HttpOnly/SameSite cookies.

### Clients & SDKs
- **Go Enterprise CLI (`av`)**: Authenticated secret operations (`secrets get/set/list`), `run`, `doctor`, `audit verify`, and local credential scanning.
- **Daemon Agent (`aegis-agent`)**: Real-time secret injection, signal forwarding, and token refresh.
- **Python SDK**: Async and sync client SDK for direct key retrieval and secret management.

### Operations & Infrastructure
- **Production Compose**: Multi-container Docker stack isolating PostgreSQL and Redis into private internal networks with Traefik TLS gateway.
- **Disaster Recovery**: Automated zero-plaintext cold backup and restore runbooks with cryptographic integrity verification.

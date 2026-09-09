# Contributing to AegisVault Fortress

1. **Plan First**: For all changes touching more than one file, author a plan under `docs/plans/`.
2. **Crypto Invariants**: Never hand-roll cryptography; always use AES-256-GCM envelope encryption with AAD binding.
3. **Zero Plaintext**: Never log or return raw secrets to unauthorized principals.
4. **Auditability**: Every secret change must generate an immutable SHA-256 chained audit record.

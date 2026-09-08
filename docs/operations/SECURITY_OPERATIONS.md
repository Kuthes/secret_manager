# AegisVault Security Operations Runbook

## Scope & Target Audience
This runbook provides actionable procedures for Site Reliability Engineers (SREs), Security Operations Center (SOC) analysts, and Security Engineers responding to incidents in AegisVault production environments.

---

## 1. Suspected Secret Compromise

### Symptoms & Alerts
- SIEM notification of unauthorized secret reveal (`secret.reveal` event).
- Secret fingerprint detected in public repositories, logs, or external bug reports.

### Immediate Containment
1. **Rotate the Secret Value Immediately**:
   ```bash
   av secrets set <KEY> <NEW_VALUE>
   ```
2. **Revoke Downstream Credentials**:
   - For database credentials: run password rotation on the underlying database engine.
   - For API keys / third-party tokens: invalidate the token in the external SaaS provider console.
3. **Query Audit Trail for Blast Radius**:
   ```bash
   GET /api/v1/audit/events?action=secret.reveal
   ```
   Identify all identities, IP addresses, and user-agents that retrieved the secret prior to rotation.

---

## 2. API Key / Machine Identity Compromise

1. **Immediate Revocation**:
   - In the AegisVault Console or API: delete or disable the compromised `APIKey` or `ServiceIdentity`.
2. **Invalidate Active Sessions**:
   - Force expiration of all active JWT access tokens issued to that identity.
3. **Audit History Inspection**:
   - Filter `audit_events` by `actor_id` to catalogue all actions taken by the compromised identity.

---

## 3. Administrator Account Compromise

1. **Revoke Administrative Roles**:
   - An independent Organization Owner demotes the compromised user:
   ```sql
   DELETE FROM organization_memberships WHERE user_id = '<COMPROMISED_USER_ID>';
   ```
2. **Invalidate Active User Sessions**:
   - Rotate `SECRET_KEY` in environment configuration to instantly invalidate all issued JWT access tokens.
3. **Enforce Password & MFA Reset**:
   - Mark `is_active = false` on the compromised user record until out-of-band identity verification is complete.

---

## 4. Master Encryption Key (MEK) Rotation & Compromise Response

If an active MEK is suspected of exposure:
1. **Generate New High-Entropy MEK**:
   ```bash
   export NEW_MEK_ID="mek-prod-v2"
   export NEW_MEK_B64=$(openssl rand -base64 32)
   ```
2. **Trigger Zero-Plaintext MEK Re-encryption**:
   - Invoke `/api/v1/kms/mek/rotate` to rewrap all Data Encryption Keys (DEKs) under the new MEK.
3. **Retire Compromised MEK**:
   - Change compromised MEK status in the KMS provider to `DISABLED` or `RETIRED`.

---

## 5. Certificate Authority (CA) Compromise

1. **Revoke CA Certificate**:
   - Set `is_revoked = true` on the compromised CA record in `pki_authorities`.
2. **Issue New CA**:
   - Generate a new Intermediate or Root CA certificate.
3. **Re-generate & Publish CRL**:
   - Call `/api/v1/pki/crl` to distribute the updated Certificate Revocation List to all ingress gateways and client services.
4. **Re-issue All Active Leaf Certificates**:
   - Batch-rotate all TLS certificates issued under the compromised CA.

---

## 6. Audit Chain Integrity Verification

To cryptographically verify the organization's audit ledger against tampering:
```bash
av audit verify
```
Or via HTTP API:
```bash
POST /api/v1/audit/verify
Authorization: Bearer <TOKEN>
```
If verification fails (`valid: false`), isolate the database instance immediately and snapshot all WAL logs for forensic investigation.

---

## 7. Emergency Break-Glass Access Procedure

In the event of total identity provider outage or administrative lockout:
1. Access the production host via secure SSH / bastion host.
2. Connect directly to the local database container via `psql`:
   ```bash
   docker exec -it aegisvault-prod-postgres psql -U postgres -d aegisvault
   ```
3. Create a temporary break-glass administrator account and record the action in the out-of-band incident ledger.

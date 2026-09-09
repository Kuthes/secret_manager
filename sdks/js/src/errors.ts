/**
 * AegisVault TypeScript SDK Errors.
 *
 * Security Invariant: Error messages must NEVER format or disclose plaintext secret values.
 */

export class AegisVaultError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AegisVaultError";
  }
}

export class AuthenticationError extends AegisVaultError {
  constructor(message: string = "AegisVault authentication failed: Invalid or missing token.") {
    super(message);
    this.name = "AuthenticationError";
  }
}

export class AuthorizationError extends AegisVaultError {
  constructor(message: string = "AegisVault authorization failed: Missing required permission.") {
    super(message);
    this.name = "AuthorizationError";
  }
}

export class SecretNotFoundError extends AegisVaultError {
  public readonly key: string;
  public readonly projectId: string;
  public readonly environmentId: string;

  constructor(key: string, projectId: string, environmentId: string) {
    super(`Secret '${key}' not found in project '${projectId}' (environment '${environmentId}').`);
    this.name = "SecretNotFoundError";
    this.key = key;
    this.projectId = projectId;
    this.environmentId = environmentId;
  }
}

export class VaultUnavailableError extends AegisVaultError {
  public readonly statusCode?: number;

  constructor(message: string, statusCode?: number) {
    super(message);
    this.name = "VaultUnavailableError";
    this.statusCode = statusCode;
  }
}

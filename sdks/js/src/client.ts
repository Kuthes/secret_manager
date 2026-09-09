import {
  AegisVaultError,
  AuthenticationError,
  AuthorizationError,
  SecretNotFoundError,
  VaultUnavailableError,
} from "./errors.js";

export interface AegisVaultOptions {
  /** AegisVault base API URL. Defaults to AEGIS_API_URL env or 'http://localhost:8000'. */
  apiUrl?: string;
  /** AegisVault service token or user Bearer token. Defaults to AEGIS_TOKEN env. */
  token?: string;
  /** Default Project ID or Slug. Defaults to AEGIS_PROJECT_ID env. */
  projectId?: string;
  /** Default Environment ID or Slug. Defaults to AEGIS_ENVIRONMENT_ID env. */
  environmentId?: string;
  /** In-memory cache TTL in milliseconds. Default: 300,000ms (5 minutes). Set to 0 to disable. */
  cacheTtlMs?: number;
  /** Network timeout in milliseconds. Default: 10,000ms (10 seconds). */
  timeoutMs?: number;
}

export interface GetSecretOptions {
  /** Override project ID. */
  projectId?: string;
  /** Override environment ID. */
  environmentId?: string;
  /** Fallback default value if secret is not found. */
  default?: string;
  /** Optional justification ticket/note for audit trail. */
  justification?: string;
  /** Bypass in-memory cache and force live fetch. */
  bypassCache?: boolean;
}

interface CacheEntry {
  value: string;
  expiresAt: number;
}

export class AegisVaultClient {
  public readonly apiUrl: string;
  private readonly token: string;
  public readonly projectId?: string;
  public readonly environmentId?: string;
  public readonly cacheTtlMs: number;
  public readonly timeoutMs: number;
  private readonly cache = new Map<string, CacheEntry>();

  constructor(options: AegisVaultOptions = {}) {
    const env = typeof process !== "undefined" && process.env ? process.env : {};

    this.apiUrl = (options.apiUrl || env.AEGIS_API_URL || "http://localhost:8000").replace(/\/+$/, "");
    this.token = options.token || env.AEGIS_TOKEN || "";
    this.projectId = options.projectId || env.AEGIS_PROJECT_ID;
    this.environmentId = options.environmentId || env.AEGIS_ENVIRONMENT_ID;
    this.cacheTtlMs = Math.max(0, options.cacheTtlMs ?? 300_000);
    this.timeoutMs = options.timeoutMs ?? 10_000;

    if (!this.token) {
      throw new AuthenticationError(
        "AegisVault token is required. Pass 'token' in constructor options or set 'AEGIS_TOKEN' environment variable."
      );
    }
  }

  /**
   * Fetch and decrypt a secret value by key name.
   *
   * @param key Secret key name (e.g. 'DATABASE_PASSWORD').
   * @param options Optional overrides for project, environment, default fallback, justification.
   */
  async get(key: string, options: GetSecretOptions = {}): Promise<string> {
    const projectId = options.projectId || this.projectId;
    const environmentId = options.environmentId || this.environmentId;

    if (!projectId || !environmentId) {
      throw new AegisVaultError(
        "Both 'projectId' and 'environmentId' are required. Set them on client initialization or in get() options."
      );
    }

    const formattedKey = key.trim().toUpperCase();
    const cacheKey = `${projectId}:${environmentId}:${formattedKey}`;

    // 1. Check in-memory cache
    if (!options.bypassCache && this.cacheTtlMs > 0) {
      const cached = this.cache.get(cacheKey);
      if (cached && Date.now() < cached.expiresAt) {
        return cached.value;
      }
    }

    // 2. Fetch from AegisVault REST API
    const url = new URL(`${this.apiUrl}/api/v1/secrets/value`);
    url.searchParams.set("project_id", projectId);
    url.searchParams.set("environment_id", environmentId);
    url.searchParams.set("key", formattedKey);
    if (options.justification) {
      url.searchParams.set("justification", options.justification);
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await fetch(url.toString(), {
        method: "GET",
        headers: {
          Authorization: `Bearer ${this.token}`,
          "User-Agent": "@aegisvault/sdk/0.1.0",
        },
        signal: controller.signal,
      });

      if (response.status === 200) {
        const data = (await response.json()) as { value: string };
        const secretValue = String(data.value ?? "");

        if (this.cacheTtlMs > 0) {
          this.cache.set(cacheKey, {
            value: secretValue,
            expiresAt: Date.now() + this.cacheTtlMs,
          });
        }
        return secretValue;
      }

      if (response.status === 404) {
        if (options.default !== undefined) {
          return options.default;
        }
        throw new SecretNotFoundError(key, projectId, environmentId);
      }

      if (response.status === 401) {
        throw new AuthenticationError("AegisVault authentication failed: Invalid or expired token.");
      }

      if (response.status === 403) {
        throw new AuthorizationError(`AegisVault authorization failed: Missing 'secret:reveal' permission for key '${key}'.`);
      }

      throw new VaultUnavailableError(
        `AegisVault server returned HTTP ${response.status}: ${response.statusText}`,
        response.status
      );
    } catch (err: unknown) {
      if (err instanceof AegisVaultError) {
        throw err;
      }
      if (err instanceof Error && err.name === "AbortError") {
        throw new VaultUnavailableError(`AegisVault request timed out after ${this.timeoutMs}ms.`);
      }
      throw new VaultUnavailableError(`Failed to connect to AegisVault at '${this.apiUrl}': ${err}`);
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Clear in-memory secret cache.
   */
  invalidateCache(key?: string): void {
    if (!key) {
      this.cache.clear();
      return;
    }
    const formattedKey = key.trim().toUpperCase();
    for (const k of this.cache.keys()) {
      if (k.endsWith(`:${formattedKey}`)) {
        this.cache.delete(k);
      }
    }
  }
}

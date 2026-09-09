const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

let authToken: string | null = null;

export function setAuthToken(token: string | null) {
  authToken = token;
}

export function getAuthToken(): string | null {
  return authToken;
}

export interface ApiSecret {
  id: string;
  project_id: string;
  environment_id: string;
  key: string;
  path: string;
  comment?: string;
  current_version: number;
  updated_at: string;
  last_actor_name?: string;
  rotation_interval?: string;
}

export interface ApiSecretVersion {
  id: string;
  version: number;
  change_type: string;
  change_message?: string;
  actor_name?: string;
  created_at: string;
}

export interface ApiProject {
  id: string;
  organization_id: string;
  name: string;
  slug: string;
  environments: Array<{
    id: string;
    project_id: string;
    name: string;
    slug: string;
    position: number;
  }>;
}

export interface ApiCertificate {
  id: string;
  ca_id: string;
  serial_number: string;
  common_name: string;
  san_dns_names: string[];
  cert_pem: string;
  valid_from: string;
  valid_to: string;
  status: string;
}

export interface ApiManagedKey {
  id: string;
  name: string;
  algorithm: string;
  key_usage: string;
  version: number;
  status: string;
  created_at: string;
}

export interface ApiAccessRequest {
  id: string;
  resource_id: string;
  resource_name?: string;
  requester_id: string;
  requester_name?: string;
  justification: string;
  duration_seconds: number;
  status: string;
  expires_at?: string;
  created_at: string;
}

export interface ApiAuditEvent {
  id: string;
  actor_name: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  result: string;
  created_at: string;
  event_hash: string;
}

async function fetchWithAuth<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string>),
  };

  if (authToken) {
    headers["Authorization"] = `Bearer ${authToken}`;
  }

  const res = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers,
    credentials: "include",
  });

  if (!res.ok) {
    const errorBody = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(errorBody.detail || "API Request Failed");
  }

  if (res.status === 204) {
    return {} as T;
  }

  return res.json();
}

export const api = {
  // Auth
  async login(email = "demo@aegisvault.local", password = "AegisDemo2026!") {
    const data = await fetchWithAuth<{ access_token: string; user_id: string; full_name: string; org_name: string }>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
    setAuthToken(data.access_token);
    return data;
  },

  // Projects
  async getProjects(): Promise<ApiProject[]> {
    return fetchWithAuth<ApiProject[]>("/projects");
  },

  // Secrets
  async getSecrets(projectId: string, environmentId: string): Promise<ApiSecret[]> {
    return fetchWithAuth<ApiSecret[]>(`/secrets?project_id=${projectId}&environment_id=${environmentId}`);
  },

  async createSecret(projectId: string, environmentId: string, payload: { key: string; value: string; path?: string; comment?: string }) {
    return fetchWithAuth<ApiSecret>(`/secrets?project_id=${projectId}&environment_id=${environmentId}`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  },

  async revealSecret(secretId: string): Promise<{ id: string; key: string; value: string; version: number }> {
    return fetchWithAuth<{ id: string; key: string; value: string; version: number }>(`/secrets/${secretId}/reveal`);
  },

  async getSecretVersions(secretId: string): Promise<ApiSecretVersion[]> {
    return fetchWithAuth<ApiSecretVersion[]>(`/secrets/${secretId}/versions`);
  },

  async rollbackSecret(secretId: string, targetVersion: number, reason?: string) {
    return fetchWithAuth<ApiSecret>(`/secrets/${secretId}/rollback`, {
      method: "POST",
      body: JSON.stringify({ target_version: targetVersion, reason }),
    });
  },

  // PKI & Certificates
  async getCertificates(): Promise<ApiCertificate[]> {
    return fetchWithAuth<ApiCertificate[]>("/pki/certificates");
  },

  // KMS
  async getKeys(): Promise<ApiManagedKey[]> {
    return fetchWithAuth<ApiManagedKey[]>("/kms/keys");
  },

  // PAM Access
  async getAccessRequests(): Promise<ApiAccessRequest[]> {
    return fetchWithAuth<ApiAccessRequest[]>("/access/requests");
  },

  // Audit Logs
  async getAuditEvents(): Promise<ApiAuditEvent[]> {
    return fetchWithAuth<ApiAuditEvent[]>("/audit/events?limit=50");
  },
};

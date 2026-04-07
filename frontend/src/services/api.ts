import type {
  AuthResponse,
  LoginCredentials,
  RegisterData,
  User,
  Conversation,
  Message,
  AgentResponse,
  Connector,
  AuditLog,
  AuditStats,
  DashboardStats,
  ScanResult,
} from "@/types";

const API_BASE = "/api";

class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
    this.name = "ApiError";
  }
}

async function request<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const token = localStorage.getItem("auth_token");

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...((options.headers as Record<string, string>) || {}),
  };

  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers,
  });

  if (!response.ok) {
    const errorBody = await response.json().catch(() => ({}));
    throw new ApiError(
      errorBody.detail || `Request failed: ${response.statusText}`,
      response.status
    );
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return response.json();
}

// Auth
export async function login(credentials: LoginCredentials): Promise<AuthResponse> {
  const data = await request<AuthResponse>("/auth/login", {
    method: "POST",
    body: JSON.stringify(credentials),
  });
  localStorage.setItem("auth_token", data.access_token);
  return data;
}

export async function register(data: RegisterData): Promise<AuthResponse> {
  const result = await request<AuthResponse>("/auth/register", {
    method: "POST",
    body: JSON.stringify(data),
  });
  localStorage.setItem("auth_token", result.access_token);
  return result;
}

export async function getMe(): Promise<User> {
  return request<User>("/auth/me");
}

export function logout(): void {
  localStorage.removeItem("auth_token");
  window.location.href = "/login";
}

// Conversations
export async function getConversations(): Promise<Conversation[]> {
  return request<Conversation[]>("/conversations");
}

export async function createConversation(title: string): Promise<Conversation> {
  return request<Conversation>("/conversations", {
    method: "POST",
    body: JSON.stringify({ title }),
  });
}

export async function getMessages(conversationId: string): Promise<Message[]> {
  return request<Message[]>(`/conversations/${conversationId}/messages`);
}

export async function sendMessage(
  conversationId: string,
  content: string
): Promise<AgentResponse> {
  return request<AgentResponse>(
    `/conversations/${conversationId}/messages`,
    {
      method: "POST",
      body: JSON.stringify({ content }),
    }
  );
}

export async function approveAction(
  approvalId: string,
  approved: boolean
): Promise<void> {
  return request<void>(`/approvals/${approvalId}`, {
    method: "POST",
    body: JSON.stringify({ approved }),
  });
}

// Connectors
export async function getConnectors(): Promise<Connector[]> {
  return request<Connector[]>("/connectors");
}

export async function addConnector(
  connector: Partial<Connector>
): Promise<Connector> {
  return request<Connector>("/connectors", {
    method: "POST",
    body: JSON.stringify(connector),
  });
}

export async function updateConnector(
  id: string,
  data: Partial<Connector>
): Promise<Connector> {
  return request<Connector>(`/connectors/${id}`, {
    method: "PATCH",
    body: JSON.stringify(data),
  });
}

export async function deleteConnector(id: string): Promise<void> {
  return request<void>(`/connectors/${id}`, { method: "DELETE" });
}

export async function testConnector(id: string): Promise<ScanResult> {
  return request<ScanResult>(`/connectors/${id}/test`, { method: "POST" });
}

// Audit Logs
export async function getAuditLogs(params?: {
  connector_id?: string;
  status?: string;
  start_date?: string;
  end_date?: string;
  search?: string;
  limit?: number;
  offset?: number;
}): Promise<AuditLog[]> {
  const searchParams = new URLSearchParams();
  if (params) {
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== "") {
        searchParams.set(key, String(value));
      }
    });
  }
  const query = searchParams.toString();
  return request<AuditLog[]>(`/audit${query ? `?${query}` : ""}`);
}

export async function getAuditStats(): Promise<AuditStats> {
  return request<AuditStats>("/audit/stats");
}

// Dashboard
export async function getDashboardStats(): Promise<DashboardStats> {
  return request<DashboardStats>("/dashboard/stats");
}

// Settings
export async function updateProfile(data: {
  name?: string;
  email?: string;
}): Promise<User> {
  return request<User>("/auth/profile", {
    method: "PATCH",
    body: JSON.stringify(data),
  });
}

export async function changePassword(data: {
  current_password: string;
  new_password: string;
}): Promise<void> {
  return request<void>("/auth/password", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export async function updateSettings(data: {
  default_permission_tier?: string;
  rate_limit?: number;
  llm_provider?: string;
  llm_model?: string;
}): Promise<void> {
  return request<void>("/settings", {
    method: "PATCH",
    body: JSON.stringify(data),
  });
}

export async function deleteAccount(): Promise<void> {
  return request<void>("/auth/account", { method: "DELETE" });
}

export async function resetConnectors(): Promise<void> {
  return request<void>("/connectors/reset", { method: "POST" });
}

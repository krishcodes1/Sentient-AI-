import type {
  AuthResponse,
  LoginCredentials,
  RegisterData,
  User,
  Conversation,
  Message,
  ChatResponse,
  Connector,
  AuditLog,
  AuditStats,
  DashboardStats,
  ScanResult,
  UpdateSettingsData,
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

// ── Auth ─────────────────────────────────────────────────────────────────

export async function login(credentials: LoginCredentials): Promise<AuthResponse> {
  const data = await request<AuthResponse>("/auth/login", {
    method: "POST",
    body: JSON.stringify(credentials),
  });
  localStorage.setItem("auth_token", data.access_token);
  localStorage.setItem("user", JSON.stringify(data.user));
  return data;
}

export async function register(data: RegisterData): Promise<AuthResponse> {
  const result = await request<AuthResponse>("/auth/register", {
    method: "POST",
    body: JSON.stringify(data),
  });
  localStorage.setItem("auth_token", result.access_token);
  localStorage.setItem("user", JSON.stringify(result.user));
  return result;
}

export async function getMe(): Promise<User> {
  return request<User>("/auth/me");
}

export function logout(): void {
  localStorage.removeItem("auth_token");
  localStorage.removeItem("user");
  window.location.href = "/login";
}

export function getStoredUser(): User | null {
  try {
    const raw = localStorage.getItem("user");
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

// ── Settings ─────────────────────────────────────────────────────────────

export async function updateSettings(data: UpdateSettingsData): Promise<User> {
  const updated = await request<User>("/auth/settings", {
    method: "PATCH",
    body: JSON.stringify(data),
  });
  localStorage.setItem("user", JSON.stringify(updated));
  return updated;
}

// ── Conversations ────────────────────────────────────────────────────────

export async function getConversations(): Promise<Conversation[]> {
  return request<Conversation[]>("/agent/conversations");
}

export async function createConversation(title: string): Promise<Conversation> {
  return request<Conversation>("/agent/conversations", {
    method: "POST",
    body: JSON.stringify({ title }),
  });
}

export async function getMessages(conversationId: string): Promise<Message[]> {
  const conv = await request<{ messages: Message[] }>(`/agent/conversations/${conversationId}`);
  return conv.messages;
}

export async function sendMessage(
  conversationId: string,
  content: string
): Promise<ChatResponse> {
  return request<ChatResponse>(
    `/agent/conversations/${conversationId}/messages`,
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

// ── Connectors ───────────────────────────────────────────────────────────

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

export async function deleteConnector(id: string): Promise<void> {
  return request<void>(`/connectors/${id}`, { method: "DELETE" });
}

export async function testConnector(id: string): Promise<ScanResult> {
  return request<ScanResult>(`/connectors/${id}/test`, { method: "POST" });
}

// ── Audit Logs ───────────────────────────────────────────────────────────

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

// ── Dashboard ────────────────────────────────────────────────────────────

export async function getDashboardStats(): Promise<DashboardStats> {
  return request<DashboardStats>("/dashboard/stats");
}

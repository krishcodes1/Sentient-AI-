import type {
  AuthResponse,
  LoginCredentials,
  RegisterData,
  User,
  Conversation,
  ConversationWithMessages,
  AgentTurnResponse,
  PendingApproval,
  ApprovalDecisionResponse,
  Connector,
  ConnectorHealthEntry,
  CreateConnectorRequest,
  AuditLog,
  AuditStats,
  DashboardStats,
  AuditLogFilters,
  AuditIntegrityCheck,
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

// Conversations and Agent
export async function getConversations(userId: string): Promise<Conversation[]> {
  const params = new URLSearchParams({ user_id: userId });
  return request<Conversation[]>(`/agent/conversations?${params.toString()}`);
}

export async function createConversation(
  userId: string,
  title: string = "New Conversation"
): Promise<Conversation> {
  return request<Conversation>("/agent/conversations", {
    method: "POST",
    body: JSON.stringify({ user_id: userId, title }),
  });
}

export async function getConversation(
  conversationId: string
): Promise<ConversationWithMessages> {
  return request<ConversationWithMessages>(`/agent/conversations/${conversationId}`);
}

export async function sendMessage(
  conversationId: string,
  userId: string,
  content: string
): Promise<AgentTurnResponse> {
  return request<AgentTurnResponse>(
    `/agent/conversations/${conversationId}/messages`,
    {
      method: "POST",
      body: JSON.stringify({ content, user_id: userId }),
    }
  );
}

export async function getPendingApprovals(userId: string): Promise<PendingApproval[]> {
  const params = new URLSearchParams({ user_id: userId });
  return request<PendingApproval[]>(`/agent/approvals?${params.toString()}`);
}

export async function decideApproval(
  actionId: string,
  userId: string,
  approved: boolean
): Promise<ApprovalDecisionResponse> {
  return request<ApprovalDecisionResponse>(`/agent/approvals/${actionId}`, {
    method: "POST",
    body: JSON.stringify({ user_id: userId, approved }),
  });
}

// Connectors
export async function getConnectors(userId: string): Promise<Connector[]> {
  const params = new URLSearchParams({ user_id: userId });
  return request<Connector[]>(`/connectors/?${params.toString()}`);
}

export async function createConnector(
  body: CreateConnectorRequest,
): Promise<Connector> {
  return request<Connector>("/connectors/", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export async function updateConnector(
  id: string,
  data: Partial<CreateConnectorRequest>,
): Promise<Connector> {
  return request<Connector>(`/connectors/${id}`, {
    method: "PATCH",
    body: JSON.stringify(data),
  });
}

export async function deleteConnector(id: string): Promise<void> {
  return request<void>(`/connectors/${id}`, { method: "DELETE" });
}

export async function getConnectorHealth(
  userId: string,
): Promise<ConnectorHealthEntry[]> {
  const params = new URLSearchParams({ user_id: userId });
  return request<ConnectorHealthEntry[]>(`/connectors/health?${params.toString()}`);
}

// Audit Logs
export async function getAuditLogs(
  userId: string,
  filters: AuditLogFilters = {}
): Promise<AuditLog[]> {
  const params = new URLSearchParams({ user_id: userId });
  if (filters.connector_name) params.set("connector_name", filters.connector_name);
  if (filters.status) params.set("status", filters.status);
  if (filters.limit != null) params.set("limit", String(filters.limit));
  if (filters.offset != null) params.set("offset", String(filters.offset));
  return request<AuditLog[]>(`/audit/?${params.toString()}`);
}

export async function verifyAuditLog(id: string): Promise<AuditIntegrityCheck> {
  return request<AuditIntegrityCheck>(`/audit/${id}/verify`);
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


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
  ConnectorTestResult,
  CreateConnectorRequest,
  UpdateConnectorRequest,
  AuditLog,
  AuditLogFilters,
  AuditIntegrityCheck,
  AuditStats,
  Memory,
  CreateMemoryRequest,
  UpdateMemoryRequest,
} from "@/types";

const API_BASE = "/api";

// Endpoints that should NOT trigger an auto-redirect on 401. Hitting
// /auth/login with the wrong password legitimately returns 401, and we
// want the Login page to render that error inline, not bounce back to
// itself.
const AUTH_EXEMPT_FROM_REDIRECT = new Set<string>([
  "/auth/login",
  "/auth/register",
]);

class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
    this.name = "ApiError";
  }
}

// FastAPI error bodies are not always strings: validation failures (422)
// return an array of {loc, msg, ...} objects. Normalize everything to a
// readable sentence so the UI never renders "[object Object]".
function errorDetailToMessage(detail: unknown, fallback: string): string {
  if (typeof detail === "string" && detail.trim()) return detail;
  if (Array.isArray(detail)) {
    const messages = detail
      .map((item) => {
        if (item && typeof item === "object" && "msg" in item) {
          const loc = Array.isArray((item as { loc?: unknown[] }).loc)
            ? (item as { loc: unknown[] }).loc.slice(1).join(".")
            : "";
          const msg = String((item as { msg: unknown }).msg);
          return loc ? `${loc}: ${msg}` : msg;
        }
        return String(item);
      })
      .filter(Boolean);
    if (messages.length) return messages.join("; ");
  }
  if (detail && typeof detail === "object") {
    try {
      return JSON.stringify(detail);
    } catch {
      /* fall through */
    }
  }
  return fallback;
}

function handleUnauthorized() {
  localStorage.removeItem("auth_token");
  clearMeCache();
  // Use replace so the broken page is not in the back-button history.
  if (window.location.pathname !== "/login") {
    window.location.replace("/login");
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

    // Token is missing, invalid, or expired. Clear it and bounce to
    // /login so the user is not stuck on a page making 401 requests
    // in a loop. Skip this for the login/register endpoints themselves
    // so wrong-password errors render inline on the form.
    if (
      response.status === 401 &&
      !AUTH_EXEMPT_FROM_REDIRECT.has(endpoint)
    ) {
      handleUnauthorized();
    }

    throw new ApiError(
      errorDetailToMessage(
        errorBody.detail,
        `Request failed: ${response.statusText}`
      ),
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
  clearMeCache();
  return data;
}

export async function register(data: RegisterData): Promise<AuthResponse> {
  // The backend's /auth/register creates the account and returns the new
  // User — but no auth token. We immediately authenticate so signup logs
  // the user straight in. Without this, the caller stores `undefined` as
  // the token and ProtectedRoute bounces the new user back to /login.
  await request<User>("/auth/register", {
    method: "POST",
    body: JSON.stringify(data),
  });
  return login({ email: data.email, password: data.password });
}

// The sidebar plus every page needs the current user, so without caching
// each component mount fires its own /auth/me (4+ requests per page load
// under StrictMode). Share one in-flight/resolved request; it is cleared on
// any auth or profile change via clearMeCache().
let meCache: Promise<User> | null = null;

export function clearMeCache(): void {
  meCache = null;
}

export async function getMe(): Promise<User> {
  if (!meCache) {
    meCache = request<User>("/auth/me").catch((err) => {
      meCache = null; // never cache a failed lookup
      throw err;
    });
  }
  return meCache;
}

export function logout(): void {
  localStorage.removeItem("auth_token");
  clearMeCache();
  window.location.href = "/login";
}

// Conversations and Agent.
// Identity comes from the JWT — the backend scopes every query to the
// authenticated user, so no user_id is ever sent from the client.
export async function getConversations(options: {
  limit?: number;
  offset?: number;
} = {}): Promise<Conversation[]> {
  const params = new URLSearchParams();
  if (options.limit != null) params.set("limit", String(options.limit));
  if (options.offset != null) params.set("offset", String(options.offset));
  const query = params.toString();
  return request<Conversation[]>(
    `/agent/conversations${query ? `?${query}` : ""}`
  );
}

export async function createConversation(
  title: string = "New Conversation"
): Promise<Conversation> {
  return request<Conversation>("/agent/conversations", {
    method: "POST",
    body: JSON.stringify({ title }),
  });
}

export async function getConversation(
  conversationId: string
): Promise<ConversationWithMessages> {
  return request<ConversationWithMessages>(`/agent/conversations/${conversationId}`);
}

export async function updateConversation(
  conversationId: string,
  data: { title: string }
): Promise<Conversation> {
  return request<Conversation>(`/agent/conversations/${conversationId}`, {
    method: "PATCH",
    body: JSON.stringify(data),
  });
}

export async function deleteConversation(conversationId: string): Promise<void> {
  return request<void>(`/agent/conversations/${conversationId}`, {
    method: "DELETE",
  });
}

export async function sendMessage(
  conversationId: string,
  content: string
): Promise<AgentTurnResponse> {
  return request<AgentTurnResponse>(
    `/agent/conversations/${conversationId}/messages`,
    {
      method: "POST",
      body: JSON.stringify({ content }),
    }
  );
}

export async function getPendingApprovals(): Promise<PendingApproval[]> {
  return request<PendingApproval[]>("/agent/approvals");
}

export async function decideApproval(
  actionId: string,
  approved: boolean
): Promise<ApprovalDecisionResponse> {
  return request<ApprovalDecisionResponse>(`/agent/approvals/${actionId}`, {
    method: "POST",
    body: JSON.stringify({ approved }),
  });
}

// Connectors
export async function getConnectors(): Promise<Connector[]> {
  return request<Connector[]>("/connectors/");
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
  data: UpdateConnectorRequest,
): Promise<Connector> {
  return request<Connector>(`/connectors/${id}`, {
    method: "PATCH",
    body: JSON.stringify(data),
  });
}

export async function deleteConnector(id: string): Promise<void> {
  return request<void>(`/connectors/${id}`, { method: "DELETE" });
}

export async function testConnector(id: string): Promise<ConnectorTestResult> {
  return request<ConnectorTestResult>(`/connectors/${id}/test`, {
    method: "POST",
  });
}

export async function getConnectorHealth(): Promise<ConnectorHealthEntry[]> {
  return request<ConnectorHealthEntry[]>("/connectors/health");
}

// Audit Logs
export async function getAuditLogs(
  filters: AuditLogFilters = {}
): Promise<AuditLog[]> {
  const params = new URLSearchParams();
  if (filters.connector_name) params.set("connector_name", filters.connector_name);
  if (filters.status) params.set("status", filters.status);
  if (filters.limit != null) params.set("limit", String(filters.limit));
  if (filters.offset != null) params.set("offset", String(filters.offset));
  const query = params.toString();
  return request<AuditLog[]>(`/audit/${query ? `?${query}` : ""}`);
}

export async function verifyAuditLog(id: string): Promise<AuditIntegrityCheck> {
  return request<AuditIntegrityCheck>(`/audit/${id}/verify`);
}

export async function getAuditStats(): Promise<AuditStats> {
  return request<AuditStats>("/audit/stats");
}

// Settings
export async function updateProfile(data: {
  name?: string;
  email?: string;
}): Promise<User> {
  const user = await request<User>("/auth/profile", {
    method: "PATCH",
    body: JSON.stringify(data),
  });
  clearMeCache();
  return user;
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
  memory_enabled?: boolean;
}): Promise<User> {
  const user = await request<User>("/auth/settings", {
    method: "PATCH",
    body: JSON.stringify(data),
  });
  clearMeCache();
  return user;
}

export async function deleteAccount(): Promise<void> {
  return request<void>("/auth/account", { method: "DELETE" });
}

// Memory
export async function getMemories(): Promise<Memory[]> {
  return request<Memory[]>("/memories/");
}

export async function createMemory(
  body: CreateMemoryRequest,
): Promise<Memory> {
  return request<Memory>("/memories/", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export async function updateMemory(
  id: string,
  data: UpdateMemoryRequest,
): Promise<Memory> {
  return request<Memory>(`/memories/${id}`, {
    method: "PATCH",
    body: JSON.stringify(data),
  });
}

export async function deleteMemory(id: string): Promise<void> {
  return request<void>(`/memories/${id}`, { method: "DELETE" });
}


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
  MemoryFilters,
  CreateMemoryRequest,
  UpdateMemoryRequest,
  Message,
  ToolCall,
  BlockedAction,
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
        // `String(null)` is the truthy string "null", which survives the
        // filter below and reaches the user as an error message reading
        // "null". Drop empties here instead.
        return item == null ? "" : String(item);
      })
      .filter(Boolean);
    if (messages.length) return messages.join("; ");
    // An array with nothing usable in it (`[]`, `[""]`) must fall back to
    // the status line. Dropping through to the object branch below would
    // JSON.stringify it — an array IS a truthy object — and the UI would
    // render the literal "[]", which is the unreadable-message problem
    // this function exists to prevent.
    return fallback;
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

/** Renew the token once it is this close to expiring. */
const REFRESH_WINDOW_SECONDS = 5 * 60;
let refreshInFlight: Promise<void> | null = null;

/** Read `exp` out of a JWT without verifying it — the server does that. */
function tokenExpiry(token: string): number | null {
  try {
    const payload = token.split(".")[1];
    if (!payload) return null;
    const base64 = payload.replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64.padEnd(
      base64.length + ((4 - (base64.length % 4)) % 4),
      "="
    );
    const claims = JSON.parse(atob(padded));
    return typeof claims.exp === "number" ? claims.exp : null;
  } catch {
    return null;
  }
}

/**
 * Renew the token before it lapses, so a long working session does not end
 * abruptly mid-action. Shares one in-flight request: a page that fires five
 * calls at once must not send five refreshes.
 *
 * A refused refresh is deliberately not fatal here — the current token is
 * still valid until its own expiry, and the existing 401 path handles the
 * end of a session. Failing loudly at this point would log the user out
 * *earlier* than doing nothing.
 */
export async function ensureFreshToken(): Promise<void> {
  const token = localStorage.getItem("auth_token");
  if (!token) return;
  const exp = tokenExpiry(token);
  if (exp === null) return;

  const secondsLeft = exp - Date.now() / 1000;
  // Already expired: nothing to extend, the 401 path owns it from here.
  if (secondsLeft <= 0 || secondsLeft > REFRESH_WINDOW_SECONDS) return;

  if (!refreshInFlight) {
    refreshInFlight = fetch(`${API_BASE}/auth/refresh`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    })
      .then(async (response) => {
        if (!response.ok) return;
        const data = await response.json();
        if (data?.access_token) {
          localStorage.setItem("auth_token", data.access_token);
        }
      })
      .catch(() => {
        /* offline or refused — see the docstring */
      })
      .finally(() => {
        refreshInFlight = null;
      });
  }
  await refreshInFlight;
}

async function request<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  await ensureFreshToken();
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
  /** Free text matched against conversation titles and message bodies. */
  q?: string;
} = {}): Promise<Conversation[]> {
  const params = new URLSearchParams();
  if (options.limit != null) params.set("limit", String(options.limit));
  if (options.offset != null) params.set("offset", String(options.offset));
  if (options.q?.trim()) params.set("q", options.q.trim());
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

export interface StreamHandlers {
  onUserMessage?: (message: Message) => void;
  onContentDelta?: (text: string) => void;
  onToolCall?: (name: string) => void;
  onToolResult?: (name: string) => void;
  onPendingApproval?: (approval: PendingApproval) => void;
  onBlocked?: (blocked: BlockedAction) => void;
  onDone?: (data: {
    content: string;
    usage?: Record<string, number>;
    tool_calls?: ToolCall[];
    pending_approvals?: PendingApproval[];
    blocked_actions?: BlockedAction[];
  }) => void;
  onSaved?: (assistant: Message | null) => void;
  onError?: (reason: string) => void;
}

/**
 * Stream an agent turn over Server-Sent Events. Uses fetch (not
 * EventSource) so the Authorization header and POST body can be sent.
 * Parses `event:`/`data:` frames and dispatches to typed handlers.
 */
export async function streamMessage(
  conversationId: string,
  content: string,
  handlers: StreamHandlers,
  signal?: AbortSignal,
): Promise<void> {
  // An agent turn can run for minutes; renewing first means a long one
  // cannot start on a token that lapses halfway through.
  await ensureFreshToken();
  const token = localStorage.getItem("auth_token");
  const response = await fetch(
    `${API_BASE}/agent/conversations/${conversationId}/messages/stream`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify({ content }),
      signal,
    },
  );

  if (!response.ok || !response.body) {
    const errorBody = await response.json().catch(() => ({}));
    if (response.status === 401) handleUnauthorized();
    throw new ApiError(
      errorDetailToMessage(errorBody.detail, `Request failed: ${response.statusText}`),
      response.status,
    );
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  // A well-formed stream always ends with a terminal event (`done`, or
  // `error` when the backend reports a failure). If the connection closes
  // without one — e.g. a proxy killed the stream mid-response — the read
  // loop below still exits normally, and callers would mistake a truncated
  // reply for a complete one.
  let sawTerminalEvent = false;

  const dispatch = (frame: string) => {
    let event = "message";
    const dataLines: string[] = [];
    for (const line of frame.split("\n")) {
      if (line.startsWith("event:")) event = line.slice(6).trim();
      else if (line.startsWith("data:")) dataLines.push(line.slice(5).trim());
    }
    if (dataLines.length === 0) return;
    let data: Record<string, unknown>;
    try {
      data = JSON.parse(dataLines.join("\n"));
    } catch {
      return;
    }
    switch (event) {
      case "user_message":
        handlers.onUserMessage?.(data.user_message as Message);
        break;
      case "content_delta":
        handlers.onContentDelta?.(String(data.text ?? ""));
        break;
      case "tool_call":
        handlers.onToolCall?.(String(data.name ?? ""));
        break;
      case "tool_result":
        handlers.onToolResult?.(String(data.name ?? ""));
        break;
      case "pending_approval":
        handlers.onPendingApproval?.(data as unknown as PendingApproval);
        break;
      case "blocked":
        handlers.onBlocked?.(data as unknown as BlockedAction);
        break;
      case "done":
        sawTerminalEvent = true;
        handlers.onDone?.(data as Parameters<NonNullable<StreamHandlers["onDone"]>>[0]);
        break;
      case "saved":
        handlers.onSaved?.((data.assistant_message ?? null) as Message | null);
        break;
      case "error":
        sawTerminalEvent = true;
        handlers.onError?.(String(data.reason ?? "Stream error"));
        break;
    }
  };

  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    let idx: number;
    while ((idx = buffer.indexOf("\n\n")) !== -1) {
      const frame = buffer.slice(0, idx);
      buffer = buffer.slice(idx + 2);
      if (frame.trim()) dispatch(frame);
    }
  }
  if (buffer.trim()) dispatch(buffer);

  if (!sawTerminalEvent) {
    throw new Error(
      "The response stream was interrupted — the reply may not have been saved. Reload to see the saved conversation.",
    );
  }
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

/**
 * Download every record this account holds as a JSON file. The response is
 * streamed and can be large, so it goes straight to a blob rather than
 * through the JSON-parsing `request` helper.
 */
export async function exportAccount(): Promise<void> {
  const token = localStorage.getItem("auth_token");
  const response = await fetch(`${API_BASE}/auth/export`, {
    headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}) },
  });
  if (!response.ok) {
    if (response.status === 401) handleUnauthorized();
    throw new ApiError("Export failed. Please try again.", response.status);
  }

  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download =
    response.headers
      .get("content-disposition")
      ?.match(/filename="([^"]+)"/)?.[1] ?? "sentientai-export.json";
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

// Memory
export async function getMemories(
  filters: MemoryFilters = {},
): Promise<Memory[]> {
  const params = new URLSearchParams();
  // A blank term is omitted rather than sent as q="" so the backend's
  // "no filter" path and this one agree.
  if (filters.q?.trim()) params.set("q", filters.q.trim());
  if (filters.category) params.set("category", filters.category);
  if (filters.limit != null) params.set("limit", String(filters.limit));
  if (filters.offset != null) params.set("offset", String(filters.offset));
  const query = params.toString();
  return request<Memory[]>(`/memories/${query ? `?${query}` : ""}`);
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


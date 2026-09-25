/**
 * The backend API client: the shared `request` helper with token refresh and 401 handling, the SSE
 * reader for streamed turns, and one function per endpoint.
 *
 * Why it exists: Every page talks to /api through this module, so auth headers, error
 * normalisation and the redirect-on-401 rule are applied once.
 */

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
  UsageSummary,
  CapabilityStatus,
  SetupStatus,
  SetupProviders,
  ProviderChoice,
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

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
    this.name = "ApiError";
  }
}

/** Machine-readable parts of a "provider not available" failure — on an
 *  HTTP error detail and on a stream `error` frame alike. */
export interface ProviderErrorInfo {
  code?: string;
  setup_url?: string;
  settings_url?: string;
}

function nonEmpty(value: unknown): value is string {
  return typeof value === "string" && value.trim() !== "";
}

/** Append where to fix a provider failure: setup when the install is not
 *  set up, Settings when only the user's own choice is unavailable.
 *  Exported so the chat bubble can find (and link) exactly the sentence
 *  added here: `withFixPointer("", info)` is that sentence on its own. */
export function withFixPointer(message: string, info: ProviderErrorInfo | Record<string, unknown>): string {
  if (nonEmpty(info.setup_url)) return `${message} Open ${info.setup_url} to finish setup.`;
  if (nonEmpty(info.settings_url)) return `${message} Change it in Settings.`;
  return message;
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
    // A missing AI provider comes back as a structured body rather than a
    // plain string: 503 `{ message, code, setup_url }` when this Crawler is
    // not set up yet, 409 `{ message, code, settings_url }` when only the
    // user's own provider choice has no key. The sentence carries no URL,
    // so the pointer is added here and the user gets an actionable line
    // instead of a raw JSON blob.
    const obj = detail as Record<string, unknown>;
    if (typeof obj.message === "string" && obj.message.trim()) {
      return withFixPointer(obj.message, obj);
    }
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
  // Best-effort server-side revocation (bumps token_epoch so the JWT dies
  // now instead of at expiry). Fire-and-forget: local sign-out must never
  // be blocked by a network failure.
  const token = localStorage.getItem("auth_token");
  if (token) {
    void fetch(`${API_BASE}/auth/logout`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      keepalive: true,
    }).catch(() => {});
  }
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

/**
 * Attachments travel as an `images` array of data URLs beside `content`.
 *
 * The key is omitted entirely when there is nothing attached, so a server
 * that has not shipped image support yet sees exactly the request it saw
 * before — only a turn that actually carries an image can be rejected by it.
 */
function turnBody(content: string, images?: string[]): string {
  return JSON.stringify(
    images && images.length > 0 ? { content, images } : { content },
  );
}

export async function sendMessage(
  conversationId: string,
  content: string,
  images?: string[]
): Promise<AgentTurnResponse> {
  return request<AgentTurnResponse>(
    `/agent/conversations/${conversationId}/messages`,
    {
      method: "POST",
      body: turnBody(content, images),
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
  /** `reason` is ready to show (a provider failure's fix pointer already
   *  appended); `info` carries the frame's code/setup_url/settings_url when
   *  it had any. */
  onError?: (reason: string, info?: ProviderErrorInfo) => void;
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
  images?: string[],
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
      body: turnBody(content, images),
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
        // The streamed event carries the tool name as `tool`; the persisted
        // shape (and our type) uses `tool_name`. Accept both.
        handlers.onBlocked?.({
          tool_name: String(data.tool_name ?? data.tool ?? ""),
          reason: String(data.reason ?? ""),
          policy: String(data.policy ?? ""),
        });
        break;
      case "done":
        sawTerminalEvent = true;
        handlers.onDone?.(data as Parameters<NonNullable<StreamHandlers["onDone"]>>[0]);
        break;
      case "saved":
        handlers.onSaved?.((data.assistant_message ?? null) as Message | null);
        break;
      case "stopped":
        // The user stopped the task. Its "Stopped." reply follows as content
        // and `done`, so there is nothing extra to show.
        break;
      case "error": {
        sawTerminalEvent = true;
        const reason = String(data.reason ?? "Stream error");
        const info: ProviderErrorInfo = {};
        if (nonEmpty(data.code)) info.code = data.code;
        if (nonEmpty(data.setup_url)) info.setup_url = data.setup_url;
        if (nonEmpty(data.settings_url)) info.settings_url = data.settings_url;
        if (Object.keys(info).length > 0) {
          // Same sentence the blocking route's 503/409 renders to.
          handlers.onError?.(withFixPointer(reason, info), info);
        } else {
          handlers.onError?.(reason);
        }
        break;
      }
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

/**
 * The Stop button: ask the signed-in user's running task to stop. The server
 * ends it at its next step (a started tool call is never cut short) with a
 * short "Stopped." reply, which arrives on the open stream like any other
 * reply and is saved with the conversation.
 */
export async function stopAgent(): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>("/agent/stop", { method: "POST" });
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

/** The browser's IANA zone, or null where the runtime cannot say. */
function browserTimeZone(): string | null {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || null;
  } catch {
    return null;
  }
}

/**
 * Sends the viewer's timezone so "today" starts at THEIR midnight; without
 * it the server counts from midnight UTC.
 */
export async function getUsageSummary(): Promise<UsageSummary> {
  const tz = browserTimeZone();
  if (!tz) return request<UsageSummary>("/usage/summary");
  try {
    return await request<UsageSummary>(
      `/usage/summary?${new URLSearchParams({ tz }).toString()}`,
    );
  } catch (err) {
    // 422: a zone the server's tz database does not know (a browser with
    // newer tzdata). A UTC "today" beats losing the whole usage panel.
    if (err instanceof ApiError && err.status === 422) {
      return request<UsageSummary>("/usage/summary");
    }
    throw err;
  }
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
  // null = follow this Crawler's default provider/model.
  llm_provider?: string | null;
  llm_model?: string | null;
  memory_enabled?: boolean;
}): Promise<User> {
  const user = await request<User>("/auth/settings", {
    method: "PATCH",
    body: JSON.stringify(data),
  });
  clearMeCache();
  return user;
}

export async function deleteAccount(data: { current_password: string }): Promise<void> {
  return request<void>("/auth/account", {
    method: "DELETE",
    body: JSON.stringify(data),
  });
}

// Capabilities / permissions
export async function getCapabilities(): Promise<CapabilityStatus[]> {
  const data = await request<{ capabilities: CapabilityStatus[] }>(
    "/capabilities",
  );
  return data.capabilities;
}

export async function updateCapabilities(
  patch: Record<string, boolean>,
): Promise<CapabilityStatus[]> {
  const data = await request<{ capabilities: CapabilityStatus[] }>(
    "/capabilities",
    { method: "PUT", body: JSON.stringify({ capabilities: patch }) },
  );
  return data.capabilities;
}

export async function requestCapabilityAccess(
  key: string,
): Promise<CapabilityStatus> {
  const data = await request<{ ok: boolean; status: CapabilityStatus }>(
    `/capabilities/${key}/request-access`,
    { method: "POST" },
  );
  return data.status;
}

export async function installCapability(
  key: string,
): Promise<{ ok: boolean; error?: string }> {
  return request(`/capabilities/${key}/install`, { method: "POST" });
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
      ?.match(/filename="([^"]+)"/)?.[1] ?? "crawler-ai-export.json";
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


// Telegram approvals.

export interface TelegramStatus {
  configured: boolean;
  linked: boolean;
  bot_username?: string | null;
}

export interface TelegramLink {
  link_url: string;
  bot_username: string;
  expires_in_minutes: number;
}

export async function getTelegramStatus(): Promise<TelegramStatus> {
  return request<TelegramStatus>("/telegram/status");
}

export async function createTelegramLink(): Promise<TelegramLink> {
  return request<TelegramLink>("/telegram/link", { method: "POST" });
}

export async function unlinkTelegram(): Promise<void> {
  return request<void>("/telegram/link", { method: "DELETE" });
}

// First-run setup.

/**
 * Whether this install still needs the /setup wizard. Deliberately a bare
 * fetch rather than `request`: the app asks this before anyone is signed
 * in, so it must not try to renew a token or bounce a 401 to /login — the
 * endpoint is public and a leftover token from a wiped install is noise.
 */
export async function getSetupStatus(): Promise<SetupStatus> {
  const response = await fetch(`${API_BASE}/setup/status`);
  if (!response.ok) {
    throw new ApiError(`Request failed: ${response.statusText}`, response.status);
  }
  return response.json();
}

/**
 * Create the first (owner) account. Only accepted while the install has no
 * users; the response carries a token, stored exactly as login() does so
 * the rest of the wizard runs authenticated.
 */
export async function createOwner(data: RegisterData): Promise<AuthResponse> {
  const result = await request<AuthResponse>("/setup/owner", {
    method: "POST",
    body: JSON.stringify(data),
  });
  localStorage.setItem("auth_token", result.access_token);
  clearMeCache();
  return result;
}

export async function getSetupProviders(): Promise<SetupProviders> {
  return request<SetupProviders>("/setup/providers");
}

/** Sends one tiny prompt with the given key; nothing is stored. */
export async function testProvider(
  body: ProviderChoice,
): Promise<{ ok: boolean; reply?: string; error?: string }> {
  return request("/setup/provider/test", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export async function saveProvider(body: ProviderChoice): Promise<void> {
  await request<{ ok: boolean }>("/setup/provider", {
    method: "PUT",
    body: JSON.stringify(body),
  });
}

export async function testTelegram(
  token: string,
): Promise<{ ok: boolean; bot_username?: string; error?: string }> {
  return request("/setup/telegram/test", {
    method: "POST",
    body: JSON.stringify({ token }),
  });
}

export async function saveTelegram(
  token: string,
): Promise<{ bot_username: string; running: boolean }> {
  return request<{ ok: boolean; bot_username: string; running: boolean }>("/setup/telegram", {
    method: "PUT",
    body: JSON.stringify({ token }),
  });
}

/** Clears the stored bot token (an environment one is untouched). Stops
 * the poller through the installation's change listener. Admin only. */
export async function removeTelegramToken(): Promise<void> {
  await request<void>("/setup/telegram", { method: "DELETE" });
}

/**
 * Open or close account sign-ups after setup (admin only). Answers 409 while
 * an explicit ALLOW_REGISTRATION=false in the server's .env locks it closed
 * (`registration_env_locked` in the setup status).
 */
export async function updateRegistration(allow: boolean): Promise<void> {
  await request<{ ok: boolean }>("/setup/registration", {
    method: "PUT",
    body: JSON.stringify({ allow_registration: allow }),
  });
}

export async function completeSetup(body: { allow_registration: boolean }): Promise<void> {
  await request<{ ok: boolean }>("/setup/complete", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

/**
 * Discards every stored provider key and the stored Telegram bot token —
 * the way out after ENCRYPTION_KEY was rotated or lost and the setup
 * status reports `secrets_unreadable`. Keys still supplied via the
 * environment are untouched.
 */
export async function clearStoredSecrets(): Promise<void> {
  await request<void>("/setup/secrets", { method: "DELETE" });
}

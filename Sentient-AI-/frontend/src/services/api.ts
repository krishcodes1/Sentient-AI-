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
  AppApproval,
  PermissionGrant,
  CanvasSchool,
  Connector,
  ConnectorHealthEntry,
  ConnectorTestResult,
  ConnectorTypeInfo,
  CreateConnectorRequest,
  UpdateConnectorRequest,
  OAuthDeviceResponse,
  OAuthDraftRequest,
  OAuthFlowStatus,
  OAuthStartResponse,
  SlackLinkCode,
  SlackLinkStatus,
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
  TurnImage,
  UploadedFile,
  BlockedAction,
  UsageSummary,
  CapabilityStatus,
  SetupStatus,
  SetupProviders,
  ProviderChoice,
  VaultItemView,
  VaultItems,
} from "@/types";
// Every request below, the raw fetches included, names this browser in
// X-Crawler-Device, so an app allowed for a week from here applies only to
// requests from here.
import { deviceHeader } from "@/services/deviceId";

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
      headers: { Authorization: `Bearer ${token}`, ...deviceHeader() },
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
    ...deviceHeader(),
    ...timezoneHeader(),
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
      headers: { Authorization: `Bearer ${token}`, ...deviceHeader() },
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
function turnBody(content: string, images?: string[], fileIds?: string[]): string {
  return JSON.stringify({
    content,
    ...(images && images.length > 0 ? { images } : {}),
    // Uploaded documents ride along by id (top10:file_extraction).
    ...(fileIds && fileIds.length > 0 ? { file_ids: fileIds } : {}),
  });
}

export async function sendMessage(
  conversationId: string,
  content: string,
  images?: string[],
  fileIds?: string[],
): Promise<AgentTurnResponse> {
  return request<AgentTurnResponse>(
    `/agent/conversations/${conversationId}/messages`,
    {
      method: "POST",
      body: turnBody(content, images, fileIds),
    }
  );
}

export interface StreamHandlers {
  onUserMessage?: (message: Message) => void;
  onContentDelta?: (text: string) => void;
  /** `phrase` is the step's plain progress line ("Searching the web…") when the server sent one. */
  onToolCall?: (name: string, phrase?: string) => void;
  onToolResult?: (name: string) => void;
  onPendingApproval?: (approval: PendingApproval) => void;
  onBlocked?: (blocked: BlockedAction) => void;
  onDone?: (data: {
    content: string;
    usage?: Record<string, number>;
    tool_calls?: ToolCall[];
    pending_approvals?: PendingApproval[];
    blocked_actions?: BlockedAction[];
    /** This turn's screenshots, sent once and never saved. */
    images?: TurnImage[];
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
  fileIds?: string[],
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
        ...deviceHeader(),
        ...timezoneHeader(),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: turnBody(content, images, fileIds),
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
        if (typeof data.phrase === "string" && data.phrase) {
          handlers.onToolCall?.(String(data.name ?? ""), data.phrase);
        } else {
          handlers.onToolCall?.(String(data.name ?? ""));
        }
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
          ...(typeof data.phrase === "string" && data.phrase ? { phrase: data.phrase } : {}),
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

/**
 * Approve or deny a parked tool call. `remember: "week"` comes from a card's
 * "Allow {app} for 7 days" button: it approves this act and allows the app
 * for 7 days, for requests from this browser. `remember: "low_risk"` comes
 * from "Allow low-risk changes on {account} for 7 days": it approves this
 * change and lets that account make low-risk changes without asking for 7
 * days. Without either the body is `{approved}` alone, exactly as before.
 */
export async function decideApproval(
  actionId: string,
  approved: boolean,
  remember?: "week" | "low_risk"
): Promise<ApprovalDecisionResponse> {
  return request<ApprovalDecisionResponse>(`/agent/approvals/${actionId}`, {
    method: "POST",
    body: JSON.stringify(remember ? { approved, remember } : { approved }),
  });
}

/** Settings ▸ Permissions ▸ Apps allowed for a week: this account's live
 *  weekly app approvals, from Telegram and from every browser. */
export async function listAppApprovals(): Promise<AppApproval[]> {
  return request<AppApproval[]>("/agent/app-approvals");
}

/** End a weekly app approval now; the next act in that app gets a card
 *  again. 404 when it is not this account's or no longer live. */
export async function revokeAppApproval(id: string): Promise<void> {
  return request<void>(`/agent/app-approvals/${id}`, { method: "DELETE" });
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

/** The connector catalog the Connectors page renders its cards and forms
 * from (one entry per registered connector; MCP is not in it). */
export async function getConnectorTypes(): Promise<ConnectorTypeInfo[]> {
  return request<ConnectorTypeInfo[]>("/connectors/types");
}

/** Schools whose name matches `query`, with their Canvas address, for the Canvas connect form.
 * The backend asks Instructure's public school search, so the browser never calls it. */
export async function searchCanvasSchools(query: string): Promise<CanvasSchool[]> {
  const params = new URLSearchParams({ q: query });
  return request<CanvasSchool[]>(`/connectors/canvas/schools?${params.toString()}`);
}

// OAuth broker. `provider` is a catalog entry's `auth.provider`.

/** Start a browser sign-in; open `authorization_url` in the system
 * browser, then poll getOAuthStatus. 503 when the server has no client id. */
export async function startOAuth(
  provider: string,
  draft: OAuthDraftRequest,
): Promise<OAuthStartResponse> {
  return request<OAuthStartResponse>(`/oauth/${encodeURIComponent(provider)}/start`, {
    method: "POST",
    body: JSON.stringify(draft),
  });
}

/** Start a device-code sign-in: the user types `user_code` at
 * `verification_uri` while the server polls the provider. */
export async function startDeviceOAuth(
  provider: string,
  draft: OAuthDraftRequest,
): Promise<OAuthDeviceResponse> {
  return request<OAuthDeviceResponse>(`/oauth/${encodeURIComponent(provider)}/device`, {
    method: "POST",
    body: JSON.stringify(draft),
  });
}

export async function getOAuthStatus(
  provider: string,
  flowId: string,
): Promise<OAuthFlowStatus> {
  const params = new URLSearchParams({ flow: flowId });
  return request<OAuthFlowStatus>(
    `/oauth/${encodeURIComponent(provider)}/status?${params.toString()}`,
  );
}

// Slack DM linking for a Slack connector that carries an app-level token.

/** A one-time code the user sends to the Crawler bot as a Slack DM. */
export async function createSlackLink(connectorId: string): Promise<SlackLinkCode> {
  return request<SlackLinkCode>(`/connectors/${encodeURIComponent(connectorId)}/slack/link`, {
    method: "POST",
  });
}

export async function getSlackLinkStatus(connectorId: string): Promise<SlackLinkStatus> {
  return request<SlackLinkStatus>(`/connectors/${encodeURIComponent(connectorId)}/slack/link`);
}

export async function unlinkSlack(connectorId: string): Promise<void> {
  await request<void>(`/connectors/${encodeURIComponent(connectorId)}/slack/link`, {
    method: "DELETE",
  });
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
 * Change one capability's settings (the purchase caps). Owner only; the
 * server answers with the whole list, like PUT /capabilities, so the page
 * can replace its state in one go.
 */
export async function updateCapabilitySettings(
  key: string,
  patch: Record<string, number>,
): Promise<CapabilityStatus[]> {
  const data = await request<{ capabilities: CapabilityStatus[] }>(
    `/capabilities/${key}/settings`,
    { method: "PUT", body: JSON.stringify({ settings: patch }) },
  );
  return data.capabilities;
}

// The card vault (owner only). The card goes to the server exactly once, in
// saveVaultCard's body; every response is the masked VaultItemView.

export interface VaultCardInput {
  label?: string;
  number: string;
  exp_month: number;
  exp_year: number;
  cvc: string;
  name: string;
}

export async function getVaultItems(): Promise<VaultItems> {
  const data = await request<Partial<VaultItems>>("/vault/items");
  // An older server answered with the items alone: read that as available.
  return {
    items: data.items ?? [],
    available: data.available !== false,
    reason: typeof data.reason === "string" ? data.reason : "",
  };
}

export async function saveVaultCard(body: VaultCardInput): Promise<VaultItemView> {
  return request<VaultItemView>("/vault/card", {
    method: "PUT",
    body: JSON.stringify(body),
  });
}

export async function deleteVaultItem(id: string): Promise<void> {
  return request<void>(`/vault/items/${id}`, { method: "DELETE" });
}

/**
 * Download every record this account holds as a JSON file. The response is
 * streamed and can be large, so it goes straight to a blob rather than
 * through the JSON-parsing `request` helper.
 */
export async function exportAccount(): Promise<void> {
  const token = localStorage.getItem("auth_token");
  const response = await fetch(`${API_BASE}/auth/export`, {
    headers: { ...deviceHeader(), ...(token ? { Authorization: `Bearer ${token}` } : {}) },
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
  const response = await fetch(`${API_BASE}/setup/status`, { headers: deviceHeader() });
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

// top10:secret_pii_redaction

// top10:file_extraction
/**
 * Uploads one document for the chat as soon as it is picked: the raw file
 * as the request body (never base64 in JSON), its type in Content-Type and
 * its name, URL-encoded, in X-File-Name. The server reads it right away and
 * answers what it found (pages, scanned pages it could not read) or why it
 * could not read it (an ApiError whose message is ready to show).
 */
export async function uploadFile(file: File, signal?: AbortSignal): Promise<UploadedFile> {
  await ensureFreshToken();
  const token = localStorage.getItem("auth_token");
  const response = await fetch(`${API_BASE}/files`, {
    method: "POST",
    headers: {
      "Content-Type": file.type || "application/octet-stream",
      "X-File-Name": encodeURIComponent(file.name || "file"),
      ...deviceHeader(),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: file,
    signal,
  });
  if (!response.ok) {
    const errorBody = await response.json().catch(() => ({}));
    if (response.status === 401) handleUnauthorized();
    throw new ApiError(
      errorDetailToMessage(errorBody.detail, `Upload failed: ${response.statusText}`),
      response.status,
    );
  }
  return response.json();
}

/** Forgets an uploaded document (its stored text); 404 when it is gone. */
export async function deleteFile(fileId: string): Promise<void> {
  await request<void>(`/files/${encodeURIComponent(fileId)}`, { method: "DELETE" });
}

// top10:scheduler_briefing
/**
 * The browser's IANA time zone as `X-Crawler-Timezone` (none where the runtime cannot say). Sent
 * with every request, so a chat message lets the server save the user's zone when it is new or
 * changed (after checking it is a real zone): scheduled tasks and the model's clock then use the
 * user's own local time even when the server runs in UTC.
 */
function timezoneHeader(): Record<string, string> {
  const zone = browserTimeZone();
  return zone ? { "X-Crawler-Timezone": zone } : {};
}

// top10:tutor_mode
import type {
  ConversationTutor,
  TutorCanvasCourses,
  TutorLock,
  TutorLockCreate,
  TutorLockList,
} from "@/types";

/** Every tutor lock on this Crawler, and whether tutor mode is on at all. Owner only (403). */
export async function listTutorLocks(): Promise<TutorLockList> {
  return request<TutorLockList>("/tutor/locks");
}

/** Create a tutor lock. A rule refusing it is a 422 whose message says why. Owner only. */
export async function createTutorLock(body: TutorLockCreate): Promise<TutorLock> {
  return request<TutorLock>("/tutor/locks", { method: "POST", body: JSON.stringify(body) });
}

/** Remove a tutor lock: the chats it held go back to each person's own switch. Owner only. */
export async function deleteTutorLock(id: string): Promise<void> {
  return request<void>(`/tutor/locks/${id}`, { method: "DELETE" });
}

/** The owner's own Canvas courses for the lock form; `available` is false without Canvas. */
export async function listTutorCanvasCourses(): Promise<TutorCanvasCourses> {
  return request<TutorCanvasCourses>("/tutor/canvas-courses");
}

/** One conversation's tutor mode. */
export async function getConversationTutor(conversationId: string): Promise<ConversationTutor> {
  return request<ConversationTutor>(`/agent/conversations/${conversationId}/tutor`);
}

/** Switch tutor mode on or off for a conversation, as /tutor on and /tutor off do. */
export async function setConversationTutor(
  conversationId: string,
  on: boolean,
): Promise<ConversationTutor> {
  return request<ConversationTutor>(`/agent/conversations/${conversationId}/tutor`, {
    method: "PUT",
    body: JSON.stringify({ on }),
  });
}

// top10:knowledge_base

// top10:flashcards_quizzes

// top10:event_triggers

// top10:permission_tiers
/** Settings ▸ Permissions ▸ Accounts allowed low-risk changes: this account's live low-risk
 *  grants, soonest to expire first. */
export async function listPermissionGrants(): Promise<PermissionGrant[]> {
  return request<PermissionGrant[]>("/agent/permission-grants");
}

/** End a low-risk grant now; that account's next change gets a card again. 404 when it is not
 *  this account's or no longer live. */
export async function revokePermissionGrant(id: string): Promise<void> {
  return request<void>(`/agent/permission-grants/${id}`, { method: "DELETE" });
}

// top10:voice_notes

// top10:video_transcripts

// Security wave (S1): outbound message checks (Security ▸ Outgoing messages).
import type { OrganisationDomain, OutboundSettings } from "@/types";

/** The outgoing-message checks' switch, the sent-to history's counts and the organisation's
 *  domains. */
export async function getOutboundSettings(): Promise<OutboundSettings> {
  return request<OutboundSettings>("/security/outbound");
}

/** Forget this account's sent-to history: every address counts as new again. */
export async function forgetKnownRecipients(): Promise<{ removed: number }> {
  return request<{ removed: number }>("/security/outbound/known-recipients", { method: "DELETE" });
}

/** Add an organisation domain. A refusal is a 409/422 whose message says why. Owner only. */
export async function addOrganisationDomain(domain: string): Promise<OrganisationDomain> {
  return request<OrganisationDomain>("/security/outbound/domains", {
    method: "POST",
    body: JSON.stringify({ domain }),
  });
}

/** Remove an organisation domain. Owner only. */
export async function removeOrganisationDomain(id: string): Promise<void> {
  return request<void>(`/security/outbound/domains/${encodeURIComponent(id)}`, { method: "DELETE" });
}

// Security wave (S2): scam checks on new email (Security ▸ Mail alerts).
import type {
  MailActionKind,
  MailAlertCard,
  MailAlertList,
  MailScanAccount,
  MailScanStatus,
} from "@/types";

/** Security ▸ Mail alerts: the switch, today's AI reviews and this account's checked mailboxes. */
export async function getMailScanStatus(): Promise<MailScanStatus> {
  return request<MailScanStatus>("/security/mail/status");
}

/** This account's mail alerts, newest first; `before` pages to older ones. */
export async function listMailAlerts(
  opts: { view?: "open" | "all"; before?: string | null; limit?: number } = {},
): Promise<MailAlertList> {
  const q = new URLSearchParams();
  q.set("view", opts.view ?? "open");
  if (opts.before) q.set("before", opts.before);
  if (opts.limit) q.set("limit", String(opts.limit));
  return request<MailAlertList>(`/security/mail/alerts?${q.toString()}`);
}

/** Make an approval card for an alert (Move to Spam/Junk). 409 when one is already waiting. */
export async function requestMailAlertAction(
  id: string,
  action: MailActionKind,
): Promise<{ card: MailAlertCard }> {
  return request<{ card: MailAlertCard }>(`/security/mail/alerts/${encodeURIComponent(id)}/actions`, {
    method: "POST",
    body: JSON.stringify({ action }),
  });
}

/** "Not a scam": takes the alert out of the open view. */
export async function dismissMailAlert(id: string): Promise<{ ok: boolean; status: string }> {
  return request<{ ok: boolean; status: string }>(`/security/mail/alerts/${encodeURIComponent(id)}/dismiss`, {
    method: "POST",
    body: "{}",
  });
}

/** Pause or resume the scam check for one of this account's mailboxes. */
export async function setMailScanPaused(connectorId: string, paused: boolean): Promise<MailScanAccount> {
  return request<MailScanAccount>(`/security/mail/accounts/${encodeURIComponent(connectorId)}`, {
    method: "PATCH",
    body: JSON.stringify({ paused }),
  });
}

// Security wave (S3): on-demand scam checks (Security ▸ Check for scams).
import type { ScamCheckRequest, ScamCheckResult, ScamCheckStatus } from "@/types";

/** Check pasted text and screenshots for scams (Security page). */
export async function checkScam(body: ScamCheckRequest): Promise<ScamCheckResult> {
  return request<ScamCheckResult>("/security/scam-check", { method: "POST", body: JSON.stringify(body) });
}

/** Whether scam checks are on, and what they can use right now. */
export async function getScamCheckStatus(): Promise<ScamCheckStatus> {
  return request<ScamCheckStatus>("/security/scam-check/status");
}

// Security wave (S4): link reputation and the owner's service keys (Security ▸ Service keys).
import type {
  LinkReputationStatus,
  SecurityKeyTestResult,
  SecurityServiceKey,
  SecurityServiceKeys,
  SecurityServiceName,
} from "@/types";

/** Every service a key can be saved for, with whether one is saved. Never a key. Owner only. */
export async function getSecurityKeys(): Promise<SecurityServiceKeys> {
  return request<SecurityServiceKeys>("/security/keys");
}

/** Tests a typed key (or, with none, the configured one); nothing is stored. */
export async function testSecurityKey(
  name: SecurityServiceName,
  key?: string,
): Promise<SecurityKeyTestResult> {
  return request<SecurityKeyTestResult>(`/security/keys/${name}/test`, {
    method: "POST",
    body: JSON.stringify(key ? { key } : {}),
  });
}

/** Tests the key and stores it only when the test passes (a failed test is a 400). */
export async function saveSecurityKey(
  name: SecurityServiceName,
  key: string,
): Promise<{ ok: boolean; service: SecurityServiceKey; detail?: string }> {
  return request<{ ok: boolean; service: SecurityServiceKey; detail?: string }>(`/security/keys/${name}`, {
    method: "PUT",
    body: JSON.stringify({ key }),
  });
}

/** Forget the stored key for one service. A key from the server's .env is not touched. */
export async function removeSecurityKey(name: SecurityServiceName): Promise<void> {
  await request<void>(`/security/keys/${name}`, { method: "DELETE" });
}

/** How link lookups are going: the service used, lookups against the limits, the last problem. */
export async function getLinkReputationStatus(): Promise<LinkReputationStatus> {
  return request<LinkReputationStatus>("/security/link-reputation/status");
}

// Security wave (S5): MCP tool pinning (Security ▸ MCP reviews and the Connectors chip).
import type {
  McpReviewList,
  McpServerApproval,
  McpToolPinView,
  McpToolReviewDetail,
} from "@/types";

/** Every MCP server's tools and how many wait for review; one server with `connectorId`. */
export async function getMcpReviews(connectorId?: string): Promise<McpReviewList> {
  const query = connectorId ? `?connector_id=${encodeURIComponent(connectorId)}` : "";
  return request<McpReviewList>(`/security/mcp/reviews${query}`);
}

/** One tool's change (or a new tool's whole definition) as diff lines, with its hash. */
export async function getMcpToolReview(pinId: string): Promise<McpToolReviewDetail> {
  return request<McpToolReviewDetail>(`/security/mcp/pins/${encodeURIComponent(pinId)}`);
}

/** Approve the version that was shown: 409 when the tool changed again since. */
export async function approveMcpTool(pinId: string, definitionHash: string): Promise<McpToolPinView> {
  return request<McpToolPinView>(`/security/mcp/pins/${encodeURIComponent(pinId)}/approve`, {
    method: "POST",
    body: JSON.stringify({ definition_hash: definitionHash }),
  });
}

/** Keep a changed or new tool off: it is not offered until approved. */
export async function keepMcpToolOff(pinId: string): Promise<McpToolPinView> {
  return request<McpToolPinView>(`/security/mcp/pins/${encodeURIComponent(pinId)}/keep-off`, {
    method: "POST",
  });
}

/** Approve every shown tool of one server at the hashes that were shown (`pins`: pin id to
 *  hash), in one request. 409 when any of them changed again: nothing is approved then. */
export async function approveMcpServer(
  connectorId: string,
  pins: Record<string, string>,
): Promise<McpServerApproval> {
  return request<McpServerApproval>(`/security/mcp/servers/${encodeURIComponent(connectorId)}/approve`, {
    method: "POST",
    body: JSON.stringify({ pins }),
  });
}

// Security wave (S6): breach monitor and the password check (Security ▸ Breach monitor).
import type { BreachAddress, BreachCheckResult, BreachFinding, BreachOverview, PwnedRange } from "@/types";

/** The owner's breach monitor: state, watched addresses and breaches seen. Owner only (403). */
export async function getBreachMonitor(): Promise<BreachOverview> {
  return request<BreachOverview>("/security/breach");
}

/** Watch one more address. A refusal is a 409/422 whose message says why. Owner only. */
export async function addBreachAddress(address: string): Promise<BreachAddress> {
  return request<BreachAddress>("/security/breach/addresses", {
    method: "POST",
    body: JSON.stringify({ address }),
  });
}

/** Pause or resume the weekly check for one address. Owner only. */
export async function setBreachAddressPaused(id: string, paused: boolean): Promise<BreachAddress> {
  return request<BreachAddress>(`/security/breach/addresses/${encodeURIComponent(id)}`, {
    method: "PATCH",
    body: JSON.stringify({ paused }),
  });
}

/** Stop watching an address and forget what was found for it. Owner only. */
export async function removeBreachAddress(id: string): Promise<void> {
  return request<void>(`/security/breach/addresses/${encodeURIComponent(id)}`, { method: "DELETE" });
}

/** Look one address up now. A failed lookup is outcome "not_checked" with a note, not an error. */
export async function checkBreachAddress(id: string): Promise<BreachCheckResult> {
  return request<BreachCheckResult>(`/security/breach/addresses/${encodeURIComponent(id)}/check`, {
    method: "POST",
  });
}

/** Mark one breach as seen. Owner only. */
export async function acknowledgeBreachFinding(id: string): Promise<BreachFinding> {
  return request<BreachFinding>(`/security/breach/findings/${encodeURIComponent(id)}/acknowledge`, {
    method: "POST",
  });
}

/** Mark every breach as seen. Owner only. */
export async function acknowledgeAllBreachFindings(): Promise<{ acknowledged: number }> {
  return request<{ acknowledged: number }>("/security/breach/findings/acknowledge-all", { method: "POST" });
}

/** Pwned Passwords range for a 5-character SHA-1 prefix. Only the prefix is sent, in the body;
 *  the browser never calls the service itself (the page's CSP allows only this server). */
export async function getPwnedRange(prefix: string): Promise<PwnedRange> {
  return request<PwnedRange>("/security/pwned-passwords/range", {
    method: "POST",
    body: JSON.stringify({ prefix }),
  });
}

// Security wave (S7): site rules for Crawler's browser (Security ▸ Site rules, owner only).
import type { SiteCategory, SiteCheck, SiteRule, SiteRuleCreate, SiteRuleKind, SiteRulesView } from "@/types";

/** The site rules, the built-in categories and recent hits. Owner only (403). */
export async function getSiteRules(): Promise<SiteRulesView> {
  return request<SiteRulesView>("/security/site-rules");
}

/** Add a rule; 422/409 carry the server's reason. Owner only. */
export async function createSiteRule(body: SiteRuleCreate): Promise<SiteRule> {
  return request<SiteRule>("/security/site-rules", { method: "POST", body: JSON.stringify(body) });
}

/** Change a rule's kind. Owner only. */
export async function updateSiteRule(id: string, kind: SiteRuleKind): Promise<SiteRule> {
  return request<SiteRule>(`/security/site-rules/${encodeURIComponent(id)}`, {
    method: "PATCH",
    body: JSON.stringify({ kind }),
  });
}

/** Remove a rule. Owner only. */
export async function deleteSiteRule(id: string): Promise<void> {
  return request<void>(`/security/site-rules/${encodeURIComponent(id)}`, { method: "DELETE" });
}

/** Set a built-in category's kind ("always_ask" resets it). Owner only. */
export async function setSiteCategory(key: string, kind: SiteRuleKind): Promise<SiteCategory> {
  return request<SiteCategory>(`/security/site-rules/categories/${encodeURIComponent(key)}`, {
    method: "PUT",
    body: JSON.stringify({ kind }),
  });
}

/** Which rule applies to a site, explained. Owner only. */
export async function checkSite(site: string): Promise<SiteCheck> {
  return request<SiteCheck>("/security/site-rules/check", { method: "POST", body: JSON.stringify({ site }) });
}

// Security wave (S9): rules on tool arguments (Security ▸ Tool rules, owner only).
import type {
  BuiltinToolRule,
  ToolRule,
  ToolRuleCatalog,
  ToolRuleCreate,
  ToolRuleDraft,
  ToolRulePreview,
  ToolRulesView,
} from "@/types";

/** The built-in rules with their switches, the owner's rules, the operators and the limits. */
export async function listToolRules(): Promise<ToolRulesView> {
  return request<ToolRulesView>("/security/tool-rules");
}

/** Add a rule. A refusal is a 422 whose message says why, shown as is. Owner only. */
export async function createToolRule(body: ToolRuleCreate): Promise<ToolRule> {
  return request<ToolRule>("/security/tool-rules", { method: "POST", body: JSON.stringify(body) });
}

/** Remove one of the owner's rules. Owner only. */
export async function deleteToolRule(id: string): Promise<void> {
  return request<void>(`/security/tool-rules/${encodeURIComponent(id)}`, { method: "DELETE" });
}

/** Turn a built-in rule on or off. Owner only. */
export async function setBuiltinToolRule(key: string, enabled: boolean): Promise<BuiltinToolRule> {
  return request<BuiltinToolRule>(`/security/tool-rules/builtins/${encodeURIComponent(key)}`, {
    method: "PUT",
    body: JSON.stringify({ enabled }),
  });
}

/** What a draft rule would match and how it reads; an invalid draft answers `valid: false`. */
export async function previewToolRule(body: ToolRuleDraft): Promise<ToolRulePreview> {
  return request<ToolRulePreview>("/security/tool-rules/preview", { method: "POST", body: JSON.stringify(body) });
}

/** The tools a rule can name, with their argument names, for the form's suggestions. */
export async function getToolRuleCatalog(): Promise<ToolRuleCatalog> {
  return request<ToolRuleCatalog>("/security/tool-rules/catalog");
}

// Security wave (S10): file reputation through VirusTotal (Security ▸ File checks).
import type { FileCheck, FileChecksResponse, FileUploadRequest } from "@/types";

/** Security ▸ File checks: the caller's own checks, newest first, and the service's state. */
export async function listFileChecks(limit = 50): Promise<FileChecksResponse> {
  return request<FileChecksResponse>(`/security/files?limit=${encodeURIComponent(String(limit))}`);
}

/** Look up a fingerprint the browser computed; the file itself is never sent. */
export async function checkFileHash(body: {
  sha256: string;
  name?: string;
  size_bytes?: number;
  media_type?: string;
}): Promise<FileCheck> {
  return request<FileCheck>("/security/files/check", { method: "POST", body: JSON.stringify(body) });
}

/**
 * Ask to send a file VirusTotal does not know; parks an approval card (nothing is uploaded
 * until it is approved). With `file`, the raw bytes are the body (as uploadFile does, never
 * base64 in JSON); without, the server uses its own copy or source.
 */
export async function requestFileUpload(checkId: string, file?: File): Promise<FileUploadRequest> {
  const endpoint = `/security/files/${encodeURIComponent(checkId)}/upload`;
  if (!file) return request<FileUploadRequest>(endpoint, { method: "POST" });
  await ensureFreshToken();
  const token = localStorage.getItem("auth_token");
  const response = await fetch(`${API_BASE}${endpoint}`, {
    method: "POST",
    headers: {
      "Content-Type": file.type || "application/octet-stream",
      ...deviceHeader(),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: file,
  });
  if (!response.ok) {
    const errorBody = await response.json().catch(() => ({}));
    if (response.status === 401) handleUnauthorized();
    throw new ApiError(
      errorDetailToMessage(errorBody.detail, `Upload failed: ${response.statusText}`),
      response.status,
    );
  }
  return response.json();
}

/** Forget one check (and any copy held for an upload). */
export async function forgetFileCheck(checkId: string): Promise<void> {
  return request<void>(`/security/files/${encodeURIComponent(checkId)}`, { method: "DELETE" });
}

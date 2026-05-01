import type {
  AuthResponse,
  LoginCredentials,
  RegisterData,
  User,
  Conversation,
  Message,
  ChatResponse,
  UpdateSettingsData,
  ChannelResponse,
  CreateChannelData,
  UpdateChannelData,
  OpenClawStatus,
  AuditLog,
  AuditStats,
  Connector,
} from "@/types";
import { API_BASE } from "@/lib/env";
import { toast } from "@/components/ui/Toaster";

/**
 * API_BASE resolves from `VITE_API_BASE_URL` (set at build time) or falls back to "/api"
 * so the Vite dev proxy and same-origin reverse-proxy deployments work without env config.
 *
 * TODO(security): move to httpOnly cookie tokens once the backend supports them.
 * Until then we keep `accessToken` and `refreshToken` in localStorage so the SPA
 * survives page reloads. Storage keys are namespaced under `sai.*`.
 */

const STORAGE_KEYS = {
  access: "sai.access_token",
  refresh: "sai.refresh_token",
  user: "user",
  // Legacy key still read on the very first migration boot.
  legacyAccess: "auth_token",
} as const;

// ── Error classes ────────────────────────────────────────────────────────

/**
 * Coerce a FastAPI / Pydantic / generic JSON error body into a single
 * human-readable string. FastAPI returns 422 as `{detail: [{loc, msg, type}, ...]}`
 * — rendering that array directly produces "[object Object]" in the UI.
 */
function formatErrorMessage(body: unknown, fallback: string): string {
  if (!body || typeof body !== "object") return fallback || "Request failed";
  const b = body as { detail?: unknown; message?: unknown; error?: unknown };
  const detail = b.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    const msgs = detail
      .map((d) => {
        if (typeof d === "string") return d;
        if (d && typeof d === "object") {
          const dd = d as { msg?: string; loc?: unknown[]; message?: string };
          const field = Array.isArray(dd.loc) && dd.loc.length > 1 ? `${String(dd.loc[dd.loc.length - 1])}: ` : "";
          return `${field}${dd.msg || dd.message || JSON.stringify(d)}`;
        }
        return String(d);
      })
      .filter(Boolean);
    if (msgs.length) return msgs.join("; ");
  }
  if (typeof b.message === "string") return b.message;
  if (typeof b.error === "string") return b.error;
  return fallback || "Request failed";
}

export class ApiError extends Error {
  status: number;
  code?: string;
  requestId?: string;
  body?: unknown;
  constructor(args: { status: number; code?: string; message: string; requestId?: string; body?: unknown }) {
    super(args.message);
    this.name = "ApiError";
    this.status = args.status;
    this.code = args.code;
    this.requestId = args.requestId;
    this.body = args.body;
  }
}

export class ServerError extends ApiError {
  constructor(args: { status: number; message: string; requestId?: string; body?: unknown }) {
    super({ ...args, code: "server_error" });
    this.name = "ServerError";
  }
}

export class NetworkError extends Error {
  constructor(message = "Network error") {
    super(message);
    this.name = "NetworkError";
  }
}

export class AccountLocked extends Error {
  lockoutUntil: Date | null;
  retryAfter: number | null;
  constructor(lockoutUntil: Date | null, retryAfter: number | null, message = "Account temporarily locked") {
    super(message);
    this.name = "AccountLocked";
    this.lockoutUntil = lockoutUntil;
    this.retryAfter = retryAfter;
  }
}

// ── Token storage ────────────────────────────────────────────────────────

export function getAccessToken(): string | null {
  // Migrate from the legacy single-token key on first read.
  const legacy = localStorage.getItem(STORAGE_KEYS.legacyAccess);
  if (legacy && !localStorage.getItem(STORAGE_KEYS.access)) {
    localStorage.setItem(STORAGE_KEYS.access, legacy);
    localStorage.removeItem(STORAGE_KEYS.legacyAccess);
  }
  return localStorage.getItem(STORAGE_KEYS.access);
}

export function getRefreshToken(): string | null {
  return localStorage.getItem(STORAGE_KEYS.refresh);
}

function setTokens(access: string, refresh?: string | null) {
  localStorage.setItem(STORAGE_KEYS.access, access);
  if (refresh) localStorage.setItem(STORAGE_KEYS.refresh, refresh);
}

function clearTokens() {
  localStorage.removeItem(STORAGE_KEYS.access);
  localStorage.removeItem(STORAGE_KEYS.refresh);
  localStorage.removeItem(STORAGE_KEYS.user);
  localStorage.removeItem(STORAGE_KEYS.legacyAccess);
}

export function getStoredUser(): User | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEYS.user);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

// ── Abort controllers ────────────────────────────────────────────────────

const inflight = new Set<AbortController>();

/** Cancel every in-flight request. Call from logout flows. */
export function cancelAll() {
  inflight.forEach((c) => {
    try {
      c.abort();
    } catch {
      /* noop */
    }
  });
  inflight.clear();
}

// ── Refresh-token coordination ───────────────────────────────────────────

let pendingRefresh: Promise<string> | null = null;

async function _refreshAccessToken(): Promise<string> {
  if (pendingRefresh) return pendingRefresh;
  const refresh = getRefreshToken();
  if (!refresh) throw new ApiError({ status: 401, code: "no_refresh_token", message: "Session expired" });

  pendingRefresh = (async () => {
    const res = await fetch(`${API_BASE}/auth/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: refresh }),
    });
    if (!res.ok) {
      throw new ApiError({ status: res.status, code: "refresh_failed", message: "Refresh failed" });
    }
    const data = (await res.json()) as { access_token: string; refresh_token?: string };
    setTokens(data.access_token, data.refresh_token ?? refresh);
    return data.access_token;
  })().finally(() => {
    pendingRefresh = null;
  });

  return pendingRefresh;
}

// ── Core request helper ──────────────────────────────────────────────────

interface RequestOptions extends Omit<RequestInit, "signal"> {
  /** Skip the 401 -> refresh flow (used internally by refresh & login). */
  skipAuthRefresh?: boolean;
  /** Skip the global toast on 5xx / network errors. */
  silent?: boolean;
}

async function request<T>(path: string, init: RequestOptions = {}, _retried = false): Promise<T> {
  const token = getAccessToken();
  const controller = new AbortController();
  inflight.add(controller);

  const baseHeaders = (init.headers as Record<string, string>) || {};
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-Request-ID": cryptoRandomId(),
    ...baseHeaders,
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers,
      signal: controller.signal,
    });
  } catch (err) {
    inflight.delete(controller);
    if ((err as Error)?.name === "AbortError") {
      throw err;
    }
    if (!init.silent) {
      toast.error({ title: "Network error", description: "Couldn't reach the server. Check your connection." });
    }
    throw new NetworkError();
  }
  inflight.delete(controller);

  if (res.status === 401 && !init.skipAuthRefresh && !_retried) {
    // Best-effort: try to refresh and retry once.
    if (getRefreshToken()) {
      try {
        await _refreshAccessToken();
        return request<T>(path, init, true);
      } catch {
        clearTokens();
        if (typeof window !== "undefined") {
          window.location.assign("/login?expired=1");
        }
        throw new ApiError({ status: 401, code: "session_expired", message: "Session expired" });
      }
    }
    // No refresh token: bail to login.
    clearTokens();
    if (typeof window !== "undefined" && !window.location.pathname.startsWith("/login")) {
      window.location.assign("/login?expired=1");
    }
    throw new ApiError({ status: 401, code: "unauthenticated", message: "Not authenticated" });
  }

  if (res.status === 429) {
    const lockoutHeader = res.headers.get("X-Lockout-Until");
    const retryAfter = res.headers.get("Retry-After");
    if (lockoutHeader) {
      const lockoutUntil = parseLockout(lockoutHeader);
      throw new AccountLocked(lockoutUntil, retryAfter ? Number(retryAfter) : null);
    }
    // Generic rate limit.
    const body = await res.json().catch(() => ({}));
    throw new ApiError({
      status: 429,
      code: body?.code || "rate_limited",
      message: formatErrorMessage(body, "Too many requests"),
      requestId: res.headers.get("X-Request-ID") || undefined,
      body,
    });
  }

  if (!res.ok) {
    const requestId = res.headers.get("X-Request-ID") || undefined;
    const body = await res.json().catch(() => ({}));
    const message = formatErrorMessage(body, res.statusText);
    if (res.status >= 500) {
      if (!init.silent) {
        toast.error({ title: "Server error", description: "Please try again." });
      }
      throw new ServerError({ status: res.status, message, requestId, body });
    }
    throw new ApiError({ status: res.status, code: body?.code, message, requestId, body });
  }

  if (res.status === 204) return null as unknown as T;

  // Some endpoints respond with no body even on 200.
  const ct = res.headers.get("content-type") || "";
  if (!ct.includes("application/json")) {
    return null as unknown as T;
  }
  return (await res.json()) as T;
}

function cryptoRandomId(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  // Fallback: not cryptographically strong, but fine as a request correlation id.
  return `req-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

function parseLockout(header: string): Date | null {
  // Accept either an HTTP-date or an ISO-8601 timestamp.
  const asNum = Number(header);
  if (!Number.isNaN(asNum) && asNum > 0) {
    // Treat numeric as seconds-from-now.
    return new Date(Date.now() + asNum * 1000);
  }
  const d = new Date(header);
  return Number.isNaN(d.getTime()) ? null : d;
}

// ── Auth ─────────────────────────────────────────────────────────────────

export async function login(credentials: LoginCredentials): Promise<AuthResponse> {
  const data = await request<AuthResponse & { refresh_token?: string }>(
    "/auth/login",
    { method: "POST", body: JSON.stringify(credentials), skipAuthRefresh: true },
  );
  setTokens(data.access_token, data.refresh_token ?? null);
  if (data.user) localStorage.setItem(STORAGE_KEYS.user, JSON.stringify(data.user));
  return data;
}

export async function register(data: RegisterData): Promise<AuthResponse> {
  const result = await request<AuthResponse & { refresh_token?: string }>(
    "/auth/register",
    { method: "POST", body: JSON.stringify(data), skipAuthRefresh: true },
  );
  setTokens(result.access_token, result.refresh_token ?? null);
  if (result.user) localStorage.setItem(STORAGE_KEYS.user, JSON.stringify(result.user));
  return result;
}

export async function logout(): Promise<void> {
  // Best-effort server logout — never block client cleanup on it.
  try {
    await request<void>("/auth/logout", { method: "POST", silent: true, skipAuthRefresh: true });
  } catch {
    /* noop */
  }
  cancelAll();
  clearTokens();
  if (typeof window !== "undefined") window.location.assign("/login");
}

export async function refresh(): Promise<string> {
  return _refreshAccessToken();
}

export async function getMe(): Promise<User> {
  return request<User>("/auth/me");
}

export interface ForgotPasswordPayload { email: string }
export async function forgotPassword(payload: ForgotPasswordPayload): Promise<{ ok: true }> {
  return request<{ ok: true }>("/auth/forgot-password", {
    method: "POST",
    body: JSON.stringify(payload),
    skipAuthRefresh: true,
  });
}

export interface ResetPasswordPayload { token: string; new_password: string }
export async function resetPassword(payload: ResetPasswordPayload): Promise<{ ok: true }> {
  return request<{ ok: true }>("/auth/reset-password", {
    method: "POST",
    body: JSON.stringify(payload),
    skipAuthRefresh: true,
  });
}

export interface VerifyEmailPayload { token: string }
export async function verifyEmail(payload: VerifyEmailPayload): Promise<{ ok: true }> {
  return request<{ ok: true }>("/auth/verify-email", {
    method: "POST",
    body: JSON.stringify(payload),
    skipAuthRefresh: true,
  });
}

export interface ResendVerificationPayload { email: string }
export async function resendVerification(payload: ResendVerificationPayload): Promise<{ ok: true }> {
  return request<{ ok: true }>("/auth/resend-verification", {
    method: "POST",
    body: JSON.stringify(payload),
    skipAuthRefresh: true,
  });
}

// ── Settings ─────────────────────────────────────────────────────────────

export async function updateSettings(data: UpdateSettingsData): Promise<User> {
  const updated = await request<User>("/auth/settings", {
    method: "PATCH",
    body: JSON.stringify(data),
  });
  localStorage.setItem(STORAGE_KEYS.user, JSON.stringify(updated));
  return updated;
}

// ── Conversations ────────────────────────────────────────────────────────

export async function getConversations(): Promise<Conversation[]> {
  return request<Conversation[]>("/agent/conversations");
}

export async function getConversation(id: string): Promise<Conversation & { messages: Message[] }> {
  return request<Conversation & { messages: Message[] }>(`/agent/conversations/${id}`);
}

export async function createConversation(title = "New conversation"): Promise<Conversation> {
  return request<Conversation>("/agent/conversations", {
    method: "POST",
    body: JSON.stringify({ title }),
  });
}

export async function deleteConversation(id: string): Promise<void> {
  return request<void>(`/agent/conversations/${id}`, { method: "DELETE" });
}

export async function getMessages(conversationId: string): Promise<Message[]> {
  const conv = await request<{ messages: Message[] }>(`/agent/conversations/${conversationId}`);
  return conv.messages;
}

export async function sendMessage(conversationId: string, content: string): Promise<ChatResponse> {
  return request<ChatResponse>(
    `/agent/conversations/${conversationId}/messages`,
    { method: "POST", body: JSON.stringify({ content }) },
  );
}

// ── Channels (OpenClaw) ──────────────────────────────────────────────────

export async function getChannels(): Promise<ChannelResponse[]> {
  return request<ChannelResponse[]>("/channels");
}

export async function createChannel(data: CreateChannelData): Promise<ChannelResponse> {
  return request<ChannelResponse>("/channels", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export async function updateChannel(id: string, data: UpdateChannelData): Promise<ChannelResponse> {
  return request<ChannelResponse>(`/channels/${id}`, {
    method: "PATCH",
    body: JSON.stringify(data),
  });
}

export async function deleteChannel(id: string): Promise<void> {
  return request<void>(`/channels/${id}`, { method: "DELETE" });
}

export async function getOpenClawStatus(): Promise<OpenClawStatus> {
  return request<OpenClawStatus>("/channels/openclaw/status");
}

export async function restartOpenClaw(): Promise<{ status: string }> {
  return request<{ status: string }>("/channels/openclaw/restart", { method: "POST" });
}

/** Browser-facing Control UI base URL (for iframe / new tab), from backend env. */
export async function getOpenClawEmbedUrl(): Promise<{ url: string }> {
  return request<{ url: string }>("/openclaw/embed-url");
}

// Backwards-compat aliases — older pages may still import these names.
export const restartOpenClawSync = restartOpenClaw;

// ── Connectors ───────────────────────────────────────────────────────────

export interface CreateConnectorPayload {
  type: string;
  name: string;
  auth_method: "oauth2" | "api_key" | "service_account";
  base_url?: string;
  permission_tier?: "open" | "supervised" | "restricted" | "locked";
  config?: Record<string, unknown>;
  credentials?: Record<string, unknown>;
}

export interface UpdateConnectorPayload {
  name?: string;
  permission_tier?: "open" | "supervised" | "restricted" | "locked";
  config?: Record<string, unknown>;
  credentials?: Record<string, unknown>;
  scopes?: string[];
}

export async function getConnectors(): Promise<Connector[]> {
  // Trailing slash matches backend route definition (`@router.get("/")`); without it
  // FastAPI 307-redirects and the browser drops the Authorization header.
  return request<Connector[]>("/connectors/");
}

export async function getConnector(id: string): Promise<Connector> {
  return request<Connector>(`/connectors/${id}`);
}

export async function createConnector(payload: CreateConnectorPayload): Promise<Connector> {
  return request<Connector>("/connectors/", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function updateConnector(id: string, patch: UpdateConnectorPayload): Promise<Connector> {
  return request<Connector>(`/connectors/${id}`, {
    method: "PATCH",
    body: JSON.stringify(patch),
  });
}

export async function deleteConnector(id: string): Promise<void> {
  return request<void>(`/connectors/${id}`, { method: "DELETE" });
}

export async function getConnectorAuthUrl(connectorType: string): Promise<{ url: string; state: string }> {
  return request<{ url: string; state: string }>(
    `/connectors/oauth/url?type=${encodeURIComponent(connectorType)}`,
  );
}

// ── Audit ────────────────────────────────────────────────────────────────

export interface AuditLogFilters {
  /** Backend query parameter names — see backend/api/routes/audit.py:202-209 */
  action?: string;
  status?: string;
  from_ts?: string;
  to_ts?: string;
  limit?: number;
  offset?: number;
}

export async function getAuditLogs(filters: AuditLogFilters = {}): Promise<AuditLog[]> {
  const params = new URLSearchParams();
  Object.entries(filters).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== "") params.set(k, String(v));
  });
  const qs = params.toString();
  // Trailing slash is intentional — FastAPI 307-redirects /audit → /audit/, and
  // browsers strip the Authorization header on the redirect (only secure for
  // same-origin same-scheme; our /api is rewritten by the dev proxy).
  return request<AuditLog[]>(`/audit/${qs ? `?${qs}` : ""}`);
}

export async function getAuditLog(id: string): Promise<AuditLog> {
  return request<AuditLog>(`/audit/${id}`);
}

export async function getAuditStats(): Promise<AuditStats> {
  return request<AuditStats>("/audit/stats");
}

export async function verifyAuditChain(): Promise<{ valid: boolean; broken_at?: string; total: number }> {
  return request<{ valid: boolean; broken_at?: string; total: number }>("/audit/verify");
}

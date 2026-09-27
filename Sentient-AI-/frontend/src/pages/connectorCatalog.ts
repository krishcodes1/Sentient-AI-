/**
 * Pure helpers for the catalog-driven Connectors page: the local MCP entry, which connect methods
 * a catalog entry can use on this server, scope grouping and default selections, credential form
 * validation and building, how an existing row may be managed, and polling timings.
 *
 * Why it exists: the page renders every card and form from GET /connectors/types, and these rules
 * (read scopes preselected, write scopes opt-in, rate limit 1 to 600, sign-in only when the server
 * has a client id) are easier to test and reuse as plain functions. A .ts module so React Fast
 * Refresh keeps working for Connectors.tsx. Depends only on the shared types in "@/types"; no
 * network.
 */

import type {
  Connector,
  ConnectorAuthKind,
  ConnectorCredentialField,
  ConnectorScopeCategory,
  ConnectorScopeInfo,
  ConnectorTypeInfo,
} from "@/types";

export const MCP_TYPE = "mcp";
export const SLACK_TYPE = "slack";

/** Backend bounds for rate_limit_per_minute (POST, PATCH and the OAuth draft). */
export const DEFAULT_RATE_LIMIT = 30;
export const MIN_RATE_LIMIT = 1;
export const MAX_RATE_LIMIT = 600;

/** How often the page polls a sign-in or a Slack link while it waits. */
export const STATUS_POLL_MS = 3000;

/** The MCP form collects headers as JSON text, sent as `credentials.headers`. */
export const HEADERS_JSON_FIELD = "headers_json";

/**
 * MCP servers are not in the backend registry (their tools are dynamic), so
 * the page keeps their entry locally, with the same fields and notice as
 * before the catalog existed.
 */
export const MCP_ENTRY: ConnectorTypeInfo = {
  key: MCP_TYPE,
  label: "MCP server",
  description:
    "Any Streamable-HTTP MCP server. Its tools appear to the agent alongside the built-in ones.",
  icon: "server",
  docs_url: "",
  creatable: true,
  auth: {
    methods: ["token"],
    fields: [
      {
        key: "url",
        label: "Server URL",
        type: "text",
        required: true,
        placeholder: "https://example.com/mcp",
        hint: "Streamable-HTTP MCP endpoint.",
      },
      {
        key: HEADERS_JSON_FIELD,
        label: "Headers (optional JSON)",
        type: "text",
        required: false,
        placeholder: '{"Authorization": "Bearer ..."}',
        hint: "Sent with every request, e.g. for authentication.",
      },
    ],
    provider: null,
    oauth_configured: false,
    token_auth_method: "bearer_token",
    notes:
      "MCP servers are third-party tools. Every tool call they expose requires your explicit approval, and tools that look financial are blocked entirely.",
  },
  scopes: { read: [], write: [] },
};

/** The entries the page offers: every creatable catalog entry, then MCP. */
export function catalogEntries(types: readonly ConnectorTypeInfo[]): ConnectorTypeInfo[] {
  const entries = types.filter((t) => t.creatable && t.key !== MCP_TYPE);
  return [...entries, MCP_ENTRY];
}

export function findEntry(
  entries: readonly ConnectorTypeInfo[],
  key: string,
): ConnectorTypeInfo | undefined {
  return entries.find((e) => e.key === key);
}

// ---------------------------------------------------------------------------
// Connect methods
// ---------------------------------------------------------------------------

export type SignInKind = Exclude<ConnectorAuthKind, "token">;

export interface ConnectOptions {
  /** Methods this server can run for the entry, in the catalog's preference order. */
  methods: ConnectorAuthKind[];
  /** The entry offers a sign-in (oauth or device) that this server has not set up. */
  signInUnavailable: boolean;
}

function isSignIn(kind: ConnectorAuthKind): kind is SignInKind {
  return kind === "oauth" || kind === "device";
}

/**
 * Which methods can actually run. A sign-in needs the broker (a provider)
 * and a client id on the server; pasting needs at least one field. When the
 * sign-in is not set up the token form, if any, is what remains.
 */
export function connectOptions(entry: ConnectorTypeInfo): ConnectOptions {
  const signInReady = Boolean(entry.auth.provider) && entry.auth.oauth_configured;
  const methods: ConnectorAuthKind[] = [];
  let signInUnavailable = false;
  for (const kind of entry.auth.methods) {
    if (methods.includes(kind)) continue;
    if (isSignIn(kind)) {
      if (signInReady) methods.push(kind);
      else signInUnavailable = true;
    } else if (kind === "token" && entry.auth.fields.length > 0) {
      methods.push(kind);
    }
  }
  return { methods, signInUnavailable };
}

/** The sign-in methods (oauth, device) this server can run for the entry. */
export function signInMethods(entry: ConnectorTypeInfo): SignInKind[] {
  return connectOptions(entry).methods.filter(isSignIn);
}

export function methodLabel(kind: ConnectorAuthKind, entry: ConnectorTypeInfo): string {
  if (kind === "oauth") return `Sign in with ${entry.label}`;
  if (kind === "device") return "Sign in with a code";
  return entry.key === MCP_TYPE ? "Server details" : "Paste a token";
}

// ---------------------------------------------------------------------------
// Scopes
// ---------------------------------------------------------------------------

/** How risky a scope looks on a chip. "financial" only comes from the
 * fallback guess: the catalog never lists financial scopes. */
export type ScopeRisk = "read" | "write" | "delete" | "financial";

export interface ScopeView {
  scope: string;
  category: ConnectorScopeCategory | "financial";
  risk: ScopeRisk;
  alwaysConfirm: boolean;
  /** Described by the catalog (false for MCP scopes and retired names). */
  known: boolean;
}

export function allScopes(entry: ConnectorTypeInfo | undefined): ConnectorScopeInfo[] {
  if (!entry) return [];
  return [...entry.scopes.read, ...entry.scopes.write];
}

export function hasScopes(entry: ConnectorTypeInfo | undefined): boolean {
  return allScopes(entry).length > 0;
}

/** Least privilege: read scopes start selected, write scopes are opt-in. */
export function defaultScopes(entry: ConnectorTypeInfo): string[] {
  return entry.scopes.read.map((s) => s.scope);
}

export function toggleScope(selected: readonly string[], scope: string): string[] {
  return selected.includes(scope)
    ? selected.filter((s) => s !== scope)
    : [...selected, scope];
}

/** The selection in catalog order (reads first), unknown names kept last,
 * duplicates dropped, so the request body does not depend on click order. */
export function orderedSelection(
  entry: ConnectorTypeInfo | undefined,
  selected: readonly string[],
): string[] {
  const chosen = new Set(selected);
  const ordered = allScopes(entry)
    .map((s) => s.scope)
    .filter((s) => chosen.has(s));
  const known = new Set(ordered);
  const rest = selected.filter((s) => !known.has(s));
  return Array.from(new Set([...ordered, ...rest]));
}

function riskOf(category: ConnectorScopeCategory): ScopeRisk {
  if (category === "read") return "read";
  if (category === "delete") return "delete";
  return "write";
}

/** Best guess for a scope the catalog does not describe (MCP, retired names). */
export function guessScopeRisk(scope: string): ScopeRisk {
  const s = scope.toLowerCase();
  if (s.includes("trade")) return "financial";
  if (s.includes("delete") || s.includes("remove")) return "delete";
  if (
    s.includes("write") ||
    s.includes("send") ||
    s.includes("create") ||
    s.includes("modify") ||
    s.includes("manage")
  ) {
    return "write";
  }
  return "read";
}

export function scopeView(entry: ConnectorTypeInfo | undefined, scope: string): ScopeView {
  const info = allScopes(entry).find((s) => s.scope === scope);
  if (info) {
    return {
      scope,
      category: info.category,
      risk: riskOf(info.category),
      alwaysConfirm: info.always_confirm,
      known: true,
    };
  }
  const risk = guessScopeRisk(scope);
  return {
    scope,
    category: risk === "financial" ? "financial" : risk,
    risk,
    alwaysConfirm: false,
    known: false,
  };
}

/** Scopes to keep when reconnecting: the row's grants the catalog still knows. */
export function reconnectScopes(entry: ConnectorTypeInfo, granted: readonly string[]): string[] {
  const known = new Set(allScopes(entry).map((s) => s.scope));
  return granted.filter((s) => known.has(s));
}

/** Catalog scopes the row does not have yet (the "Grant more access" choices). */
export function grantableScopes(
  entry: ConnectorTypeInfo,
  granted: readonly string[],
): ConnectorScopeInfo[] {
  const have = new Set(granted);
  return allScopes(entry).filter((s) => !have.has(s.scope));
}

// ---------------------------------------------------------------------------
// Credential form
// ---------------------------------------------------------------------------

export type FieldValues = Record<string, string>;

function isHttpUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return (url.protocol === "https:" || url.protocol === "http:") && url.hostname !== "";
  } catch {
    return false;
  }
}

/** `value` when it is an absolute http(s) URL, else null: a link or window
 * the page opens (docs, consent page, device verification page) can never
 * be a javascript: or data: URL, whatever a response carried. */
export function externalUrl(value: string | null | undefined): string | null {
  if (!value) return null;
  return isHttpUrl(value) ? value : null;
}

/** The problem with one field's value, or null. A blank optional field is fine. */
export function fieldError(field: ConnectorCredentialField, raw: string | undefined): string | null {
  const value = (raw ?? "").trim();
  if (!value) return field.required ? `${field.label} is required.` : null;
  if (field.type === "url" && !isHttpUrl(value)) {
    return "Enter a full web address, starting with https://";
  }
  return null;
}

/** Problems keyed by field, only for fields with a value (blank required
 * fields disable submit instead of shouting before the user has typed). */
export function visibleFieldErrors(
  fields: readonly ConnectorCredentialField[],
  values: FieldValues,
): Record<string, string> {
  const errors: Record<string, string> = {};
  for (const field of fields) {
    if (!(values[field.key] ?? "").trim()) continue;
    const problem = fieldError(field, values[field.key]);
    if (problem) errors[field.key] = problem;
  }
  return errors;
}

/** Every required field is filled and no field is invalid. */
export function isFormComplete(
  fields: readonly ConnectorCredentialField[],
  values: FieldValues,
): boolean {
  return fields.every((f) => fieldError(f, values[f.key]) === null);
}

export function anyFieldEntered(
  fields: readonly ConnectorCredentialField[],
  values: FieldValues,
): boolean {
  return fields.some((f) => (values[f.key] ?? "").trim() !== "");
}

/**
 * The credentials object for POST or PATCH: trimmed values, blanks left
 * out, and MCP's headers JSON parsed into `headers`. Throws SyntaxError when
 * that JSON is invalid.
 */
export function buildCredentials(
  fields: readonly ConnectorCredentialField[],
  values: FieldValues,
): Record<string, unknown> {
  const credentials: Record<string, unknown> = {};
  for (const field of fields) {
    const raw = (values[field.key] ?? "").trim();
    if (!raw) continue;
    if (field.key === HEADERS_JSON_FIELD) {
      credentials["headers"] = JSON.parse(raw);
    } else {
      credentials[field.key] = raw;
    }
  }
  return credentials;
}

export function clampRateLimit(value: number): number {
  const n = Math.trunc(Number(value)) || MIN_RATE_LIMIT;
  return Math.max(MIN_RATE_LIMIT, Math.min(MAX_RATE_LIMIT, n));
}

// ---------------------------------------------------------------------------
// Existing rows
// ---------------------------------------------------------------------------

/**
 * How an existing row is managed:
 * - "unavailable": its type is gone from this server; it can only be removed.
 * - "mcp": the MCP form, as always.
 * - "oauth": created by a sign-in; Reconnect and Grant more access replace
 *   pasting (a pasted set would wipe the refresh token).
 * - "oauth_or_token": the type's sign-in and pasted tokens both store
 *   auth_method "oauth2" (Google), so the row may be either: it gets the
 *   sign-in actions and keeps the paste form.
 * - "token": a pasted-credential row, edited as before.
 */
export type RowKind = "unavailable" | "mcp" | "oauth" | "oauth_or_token" | "token";

export function isRowAvailable(row: Connector): boolean {
  return row.available !== false;
}

export function rowKind(row: Connector, entry: ConnectorTypeInfo | undefined): RowKind {
  if (!isRowAvailable(row)) return "unavailable";
  if (row.connector_type === MCP_TYPE) return "mcp";
  if (!entry) return "token";
  if (entry.auth.provider && row.auth_method === "oauth2") {
    const pasteAlsoOauth2 =
      entry.auth.methods.includes("token") &&
      entry.auth.fields.length > 0 &&
      entry.auth.token_auth_method === "oauth2";
    return pasteAlsoOauth2 ? "oauth_or_token" : "oauth";
  }
  return "token";
}

// ---------------------------------------------------------------------------
// Polling
// ---------------------------------------------------------------------------

/** Delay between polls: the provider's interval for a device sign-in
 * (bounded to 1 to 30 s), otherwise every three seconds. */
export function pollDelayMs(intervalSeconds?: number | null): number {
  if (intervalSeconds == null || !Number.isFinite(intervalSeconds) || intervalSeconds <= 0) {
    return STATUS_POLL_MS;
  }
  return Math.min(30, Math.max(1, Math.round(intervalSeconds))) * 1000;
}

/** True once `iso` is in the past. An unparsable time never expires here;
 * the server's own status says when it does. */
export function isExpired(iso: string | null | undefined, now: number = Date.now()): boolean {
  if (!iso) return false;
  const at = Date.parse(iso);
  return Number.isFinite(at) && at <= now;
}

/** How far this device's clock may run ahead of the server's before a wait
 * gives up early. The server's own answer ("expired", or a Slack code no
 * longer pending) is what ends a wait; the local clock is only consulted
 * when the server cannot be reached, as a generous upper bound. */
export const EXPIRY_GRACE_MS = 2 * 60 * 1000;

/** True once `iso` plus the clock-skew grace is in the past. */
export function isPastDeadline(iso: string | null | undefined, now: number = Date.now()): boolean {
  return isExpired(iso, now - EXPIRY_GRACE_MS);
}

/** A short local time ("3:05 PM") for an expiry, or "" when unparsable. */
export function formatTime(iso: string | null | undefined): string {
  if (!iso) return "";
  const at = Date.parse(iso);
  if (!Number.isFinite(at)) return "";
  return new Date(at).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
}

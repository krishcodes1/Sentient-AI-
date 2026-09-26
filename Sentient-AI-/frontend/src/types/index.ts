/**
 * TypeScript interfaces and unions mirroring the backend's request and response shapes.
 *
 * Why it exists: The api client and every page share these, so a backend field change is made in
 * one place; the comments record which backend models each shape mirrors.
 */

export interface User {
  id: string;
  email: string;
  name: string | null;
  is_active?: boolean;
  is_admin?: boolean;
  created_at: string;
  default_permission_tier: PermissionTier;
  rate_limit: number;
  /** null = the account follows this Crawler's default provider/model. */
  llm_provider?: string | null;
  llm_model?: string | null;
  memory_enabled?: boolean;
}

export type MemoryCategory = "profile" | "preference" | "project" | "fact";
export type MemorySource = "user" | "agent";

export interface Memory {
  id: string;
  content: string;
  category: MemoryCategory;
  source: MemorySource;
  created_at: string;
  updated_at: string;
}

export interface CreateMemoryRequest {
  content: string;
  category?: MemoryCategory;
}

export interface UpdateMemoryRequest {
  content?: string;
  category?: MemoryCategory;
}

export interface MemoryFilters {
  /**
   * Free text, matched case-insensitively as a substring of memory content.
   * Blank/whitespace means "no filter"; the backend rejects anything longer
   * than its search cap (200 chars) with a 422.
   */
  q?: string;
  category?: MemoryCategory;
  limit?: number;
  offset?: number;
}

export type PermissionTier =
  | "auto_approve"
  | "user_confirm"
  | "admin_only"
  | "hard_blocked";

// "custom" is no longer creatable (the backend rejects it with 422) but
// stays in the union so connectors created before that change still render.
export type ConnectorType =
  | "canvas"
  | "google_workspace"
  | "robinhood"
  | "mcp"
  | "custom";

export type AuthMethod = "oauth2" | "api_key" | "bearer_token";

export interface Connector {
  id: string;
  user_id: string;
  connector_type: ConnectorType;
  display_name: string;
  is_active: boolean;
  auth_method: AuthMethod;
  granted_scopes: string[];
  permission_tier: PermissionTier;
  rate_limit_per_minute: number;
  created_at: string;
  updated_at: string;
}

export interface CreateConnectorRequest {
  connector_type: ConnectorType;
  display_name: string;
  auth_method: AuthMethod;
  credentials: Record<string, unknown>;
  granted_scopes?: string[];
  permission_tier?: PermissionTier;
  rate_limit_per_minute?: number;
}

// Mirrors the backend's ConnectorUpdateRequest (PATCH /connectors/{id}).
// Omitted fields keep their stored value; credentials, when present,
// replace the encrypted set wholesale.
export interface UpdateConnectorRequest {
  display_name?: string;
  is_active?: boolean;
  credentials?: Record<string, unknown>;
  granted_scopes?: string[];
  permission_tier?: PermissionTier;
  rate_limit_per_minute?: number;
}

export interface ConnectorTestResult {
  ok: boolean;
  detail: string;
}

export type AuditStatus = "approved" | "blocked" | "pending";

export interface AuditLog {
  id: string;
  user_id: string;
  timestamp: string;
  connector_name: string;
  action: string;
  endpoint: string;
  scope_used: string;
  status: AuditStatus;
  reasoning_chain?: Record<string, unknown> | unknown[] | string | null;
  detection_method?: string | null;
  confidence_score?: number | null;
  request_data?: Record<string, unknown> | null;
  response_summary?: string | null;
  integrity_hash: string;
  previous_hash?: string | null;
  request_id: string;
}

export interface AuditLogFilters {
  connector_name?: string;
  status?: AuditStatus;
  limit?: number;
  offset?: number;
}

export interface AuditIntegrityCheck {
  id: string;
  valid: boolean;
}

export interface Conversation {
  id: string;
  user_id: string;
  title: string;
  created_at: string;
  updated_at: string;
}

export interface ConversationWithMessages extends Conversation {
  messages: Message[];
  total_input_tokens?: number;
  total_output_tokens?: number;
}

export interface Message {
  id: string;
  conversation_id: string;
  role: "user" | "assistant" | "system";
  content: string;
  tool_calls?: ToolCall[] | null;
  blocked_actions?: BlockedAction[];
  created_at: string;
  /**
   * Attachments on a user turn, as data URLs. Optional because the backend
   * only started returning them alongside image support, so rows written
   * before that — and any server without it — simply have none.
   */
  images?: string[] | null;
  /**
   * What the provider billed for an assistant turn. Null when the turn
   * reported nothing (a cached replay, a provider without counts) — not
   * the same as zero, so the UI shows no caption rather than "0 in".
   */
  input_tokens?: number | null;
  output_tokens?: number | null;
  /** The part of `input_tokens` served from the provider's prompt cache
   *  (included in it, not extra). Null where the provider never said. */
  cache_read_tokens?: number | null;
  cache_write_tokens?: number | null;
  llm_provider?: string | null;
  llm_model?: string | null;
  /** Client-only: this bubble is a failed turn (never persisted). */
  error?: boolean;
  /** Client-only: the user content to resend when Retry is clicked. */
  retry_content?: string;
  /** Client-only: the attachments to resend with `retry_content`, so a
   *  retried turn carries the images the first attempt did. */
  retry_images?: string[];
  /** Client-only: a failed turn's provider-error pointer (the stream error
   *  frame's code and setup_url/settings_url), so the bubble can link to
   *  where it is fixed. */
  provider_error?: { code?: string; setup_url?: string; settings_url?: string };
  /** Client-only: the screenshots this turn's tools took. They arrive with
   *  the live turn and are never saved, so a reloaded thread has none. */
  screenshots?: TurnImage[];
}

export interface ToolCall {
  name: string;
  result?: unknown;
  tool_call_id?: string | null;
}

/** A screenshot a tool took this turn, delivered to the live view only (the
 *  saved tool call keeps a placeholder). `index` is the tool call it belongs
 *  to; `tool` and `source` (the page's host or the app) name it. */
export interface TurnImage {
  tool: string;
  source?: string | null;
  index: number;
  data_url: string;
}

export interface PendingApproval {
  action_id: string;
  tool_name: string;
  arguments: Record<string, unknown>;
  reason: string;
  expires_at?: string | null;
  // Present on GET /agent/approvals so Chat can scope cards to the open
  // conversation; approvals without it are shown everywhere.
  conversation_id?: string | null;
  // Set by the backend when the request was shaped by external/untrusted
  // content (prompt-injection heuristics). The UI must surface it as a
  // warning the user cannot miss before they approve.
  risk_note?: string | null;
  /** A browser.checkout card's screenshot of the page it was made from, as
   *  a data URL. Held in the server's memory only, so it is absent after a
   *  restart and never on any other tool's card. */
  image?: string | null;
}

/**
 * The `_checkout` block the backend stores with a browser.checkout approval:
 * what its toolkit read from the page (never what the model said), plus the
 * masked label of the stored card. It carries no card data and no image.
 */
export interface PurchaseCard {
  checkout_id: string;
  origin: string;
  host: string;
  /** Decimal string, e.g. "23.40". */
  amount_usd: string;
  currency: string;
  items: string[];
  /** e.g. "Visa ····4242". */
  card_label: string;
  notice: string;
}

export interface BlockedAction {
  tool_name: string;
  reason: string;
  policy: string;
}

export interface AgentTurnResponse {
  user_message: Message;
  assistant_message: Message;
  tool_calls: ToolCall[];
  pending_approvals: PendingApproval[];
  blocked_actions: BlockedAction[];
  images?: TurnImage[];
}

export interface ApprovalDecisionResponse {
  action_id: string;
  approved: boolean;
  result?: Record<string, unknown> | null;
  /** The pictures the approved call itself took (a checkout's confirmation
   *  page), for the live view only: the saved row keeps a placeholder. */
  images?: TurnImage[];
  /** The transcript row that records the decision, which `images` belong under. */
  message_id?: string | null;
}

export interface ConnectorHealthEntry {
  id: string;
  name: string;
  type: string;
  status: "healthy" | "degraded" | "unhealthy";
  uptime: number;
  last_check: string;
}

// Server-computed dashboard stats (GET /audit/stats). Counting happens in
// the database, so the numbers stay correct past the 500-row fetch cap.
export interface AuditStatsDay {
  date: string;
  approved: number;
  blocked: number;
  pending: number;
}

export interface AuditStats {
  total_actions_24h: number;
  blocked_24h: number;
  approved_24h: number;
  pending_approvals: number;
  by_day: AuditStatsDay[];
}

// GET /usage/summary. Costs are estimates at list prices; null means every
// turn in that scope was on a model with no known price.
export interface UsageWindow {
  input_tokens: number;
  output_tokens: number;
  /** Parts of `input_tokens` read from / written to the prompt cache.
   *  Optional so a server predating them still type-checks. */
  cache_read_tokens?: number;
  cache_write_tokens?: number;
  total_tokens: number;
  turns: number;
  estimated_cost_usd: number | null;
  /** Turns counted in the token totals but left out of the cost. */
  unpriced_turns: number;
}

export interface ModelUsage {
  provider: string | null;
  model: string | null;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens?: number;
  cache_write_tokens?: number;
  total_tokens: number;
  turns: number;
  estimated_cost_usd: number | null;
}

export interface UsageSummary {
  windows: {
    today: UsageWindow;
    last_7_days: UsageWindow;
    last_30_days: UsageWindow;
    all_time: UsageWindow;
  };
  by_model: ModelUsage[];
  currency: "USD";
  pricing_note: string;
}

export interface LoginCredentials {
  email: string;
  password: string;
}

export interface RegisterData {
  email: string;
  password: string;
  name: string;
}

// The backend's TokenResponse: /auth/login returns only the token pair.
// The user object is fetched separately via GET /auth/me.
export interface AuthResponse {
  access_token: string;
  token_type: string;
}

// Capabilities / permissions (GET|PUT /capabilities, POST .../request-access,
// POST .../install). `enabled` is the user's stored preference; `effective`
// is what actually happens right now once availability and the OS probe are
// folded in — a capability can be enabled and still be "blocked".
export type CapabilityEffective = "on" | "off" | "blocked";
export type ProbeState = "granted" | "denied" | "not_required" | "unknown";

export interface CapabilityStatus {
  key: string;
  label: string;
  description: string;
  risk: "low" | "medium" | "high";
  enabled: boolean;
  default_enabled: boolean;
  available: boolean;
  availability_reason: string;
  probe_state: ProbeState;
  probe_detail: string;
  fix_url: string | null;
  fix_steps: string[];
  effective: CapabilityEffective;
  reason: string;
  can_request_access: boolean;
  install: string | null;
  /** What the install downloads, for the Install button's label
   *  (e.g. "~150-300 MB download"); null when the server has no estimate. */
  install_size_hint: string | null;
  when_denied: string;
  tools: string[];
  /** Per-capability settings the owner can edit (the purchase caps for
   *  `purchases`), defaults already merged in by the server. Optional so a
   *  server predating them still type-checks. */
  settings?: Record<string, unknown>;
}

// The card vault (GET /vault/items, PUT /vault/card, DELETE /vault/items/{id}).
// This masked view is the only shape the server ever returns: no number, no
// CVC, no ciphertext.
/** GET /vault/items: the masked views plus whether a card can be stored on
 *  this install at all (a container has no Keychain or DPAPI for the key)
 *  and, when not, the reason to show instead of the form. */
export interface VaultItems {
  items: VaultItemView[];
  available: boolean;
  reason: string;
}

export interface VaultItemView {
  id: string;
  kind: "card" | "login";
  label: string;
  origins: string[];
  /** e.g. "Visa ····4242" or "j***@school.edu". */
  masked: string;
  brand: string;
  last4: string;
  created_at: string;
  last_used_at: string | null;
}

// First-run setup (GET /api/setup/status and the /api/setup/* writes).
export interface SetupStatus {
  needs_setup: boolean;
  has_owner: boolean;
  provider_configured: boolean;
  setup_completed: boolean;
  /** Stored secrets exist that the current ENCRYPTION_KEY cannot open;
   * the provider step should offer to clear them (DELETE /setup/secrets). */
  secrets_unreadable: boolean;
  /** Whether anyone may create an account at /login right now. */
  registration_open: boolean;
  /** An explicit ALLOW_REGISTRATION=false in the server's .env keeps
   * registration closed; PUT /setup/registration answers 409 while set. */
  registration_env_locked: boolean;
}

export interface SetupProvider {
  name: string;
  /** The key comes from the server's .env, which always wins over the DB. */
  key_from_env: boolean;
  /** A key was already saved through the wizard and is held encrypted. */
  key_stored: boolean;
  /** Suggested model ids, best default first. */
  models: string[];
}

export interface SetupProviders {
  providers: SetupProvider[];
  current: { provider: string; model: string };
}

export interface ProviderChoice {
  provider: string;
  model: string;
  /** Omitted when the server already holds the key. */
  api_key?: string;
}

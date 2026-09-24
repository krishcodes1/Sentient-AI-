export interface User {
  id: string;
  email: string;
  name: string | null;
  is_active?: boolean;
  created_at: string;
  default_permission_tier: PermissionTier;
  rate_limit: number;
  llm_provider?: string;
  llm_model?: string;
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
}

export interface ToolCall {
  name: string;
  result?: unknown;
  tool_call_id?: string | null;
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
}

export interface ApprovalDecisionResponse {
  action_id: string;
  approved: boolean;
  result?: Record<string, unknown> | null;
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

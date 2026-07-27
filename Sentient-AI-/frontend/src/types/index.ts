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
}

export interface Message {
  id: string;
  conversation_id: string;
  role: "user" | "assistant" | "system";
  content: string;
  tool_calls?: ToolCall[] | null;
  blocked_actions?: BlockedAction[];
  created_at: string;
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

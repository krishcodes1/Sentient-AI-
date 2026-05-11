export interface User {
  id: string;
  email: string;
  name: string;
  created_at: string;
  default_permission_tier: PermissionTier;
  rate_limit: number;
}

export type PermissionTier = "open" | "supervised" | "restricted" | "locked";

export interface Connector {
  id: string;
  name: string;
  type: string;
  auth_method: "oauth2" | "api_key" | "service_account";
  status: "connected" | "disconnected" | "error";
  scopes: ConnectorScope[];
  permission_tier: PermissionTier;
  base_url: string;
  created_at: string;
  last_used?: string;
  health?: "healthy" | "degraded" | "unhealthy";
}

export interface ConnectorScope {
  name: string;
  description: string;
  risk_level: "read" | "write" | "admin" | "financial";
  granted: boolean;
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
  pending_approvals?: PendingApproval[];
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

export interface ScanResult {
  safe: boolean;
  threats: string[];
  risk_score: number;
  details: Record<string, unknown>;
}

export interface PermissionDecision {
  allowed: boolean;
  reason: string;
  tier: PermissionTier;
  requires_approval: boolean;
}

export interface DashboardStats {
  active_connectors: number;
  total_actions_24h: number;
  blocked_threats: number;
  pending_approvals: number;
  recent_activity: ActivityEntry[];
  security_timeline: SecurityTimelineEntry[];
  connector_health: ConnectorHealthEntry[];
}

export interface ActivityEntry {
  id: string;
  connector: string;
  action: string;
  status: "approved" | "blocked" | "pending";
  timestamp: string;
}

export interface SecurityTimelineEntry {
  date: string;
  approved: number;
  blocked: number;
}

export interface ConnectorHealthEntry {
  id: string;
  name: string;
  type: string;
  status: "healthy" | "degraded" | "unhealthy";
  uptime: number;
  last_check: string;
}

export interface AuditStats {
  total: number;
  approved: number;
  blocked: number;
  pending: number;
  by_connector: Record<string, number>;
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

export interface AuthResponse {
  access_token: string;
  token_type: string;
  user: User;
}

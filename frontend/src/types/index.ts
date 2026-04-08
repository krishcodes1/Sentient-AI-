export interface User {
  id: string;
  email: string;
  name: string | null;
  is_active: boolean;
  llm_provider: string;
  llm_model: string;
  onboarding_completed: boolean;
  created_at: string;
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

export interface AuditLog {
  id: string;
  connector_id: string;
  connector_name: string;
  action: string;
  endpoint: string;
  scope: string;
  status: "approved" | "blocked" | "pending" | "escalated";
  decision_method: "auto" | "user" | "policy";
  reasoning: string;
  detection_method?: string;
  confidence_score?: number;
  request_data?: Record<string, unknown>;
  response_summary?: string;
  integrity_hash: string;
  integrity_valid: boolean;
  timestamp: string;
  user_id: string;
}

export interface Conversation {
  id: string;
  title: string;
  created_at: string;
  updated_at: string;
}

export interface Message {
  id: string;
  conversation_id: string;
  role: "user" | "assistant" | "system";
  content: string;
  tool_calls?: ToolCall[];
  pending_approvals?: PendingApproval[];
  created_at?: string;
  timestamp?: string;
}

export interface ToolCall {
  id: string;
  connector: string;
  action: string;
  endpoint: string;
  status: "success" | "blocked" | "pending" | "error";
  result?: string;
}

export interface PendingApproval {
  id: string;
  connector: string;
  action: string;
  scope: string;
  risk_level: "read" | "write" | "admin" | "financial";
  reasoning: string;
}

export interface AgentResponse {
  message: Message;
  tool_calls: ToolCall[];
  pending_approvals: PendingApproval[];
}

export interface ChatResponse {
  user_message: Message;
  assistant_message: Message;
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

export interface UpdateSettingsData {
  name?: string;
  llm_provider?: string;
  llm_model?: string;
  llm_api_key?: string;
  onboarding_completed?: boolean;
}

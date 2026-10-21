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
  // "Allow low-risk changes": only actions graded LOW run without asking.
  | "low_risk"
  | "user_confirm"
  | "admin_only"
  | "hard_blocked";

// A connector registry key (GET /connectors/types), "mcp", or a type stored
// before its connector left the registry (the legacy "custom" among them).
// The backend column is a plain string validated against the registry, so
// the frontend keeps it open rather than listing the keys by hand.
export type ConnectorType = string;

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
  /** False when this server can no longer use the row's type (its
   * connector left the registry, or the legacy "custom"). Such a row is
   * listed so it can be deleted and is never offered to the agent. Older
   * servers omit it, which means available. */
  available?: boolean;
  /** True when the provider refused this sign-in's refresh token, so the
   * user must Reconnect before the agent can use it. Cleared by a
   * reconnect. Older servers omit it. */
  needs_reconnect?: boolean;
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
  /** On success, where the check landed (Canvas school address, Slack or Notion workspace), when
   *  the service says; absent from servers that predate it. */
  account?: string | null;
  /** On success, who the connection acts as (Canvas name, Slack bot, GitHub login). */
  user?: string | null;
}

/** One result of GET /connectors/canvas/schools: a school and its Canvas host. */
export interface CanvasSchool {
  name: string;
  /** A bare hostname such as "nyit.instructure.com". */
  domain: string;
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

/** One labelled value an approval card shows ("To", "priya@acme.com"), in everyday words. A value
 *  on several lines keeps every line, joined with line breaks. */
export interface ApprovalDetail {
  label: string;
  value: string;
}

export interface PendingApproval {
  action_id: string;
  /** The tool id ("google_workspace.send_email"). Never shown on the card itself, only under its
   *  "Technical details". */
  tool_name: string;
  arguments: Record<string, unknown>;
  /** The card's plain first sentence ("Send an email to priya@acme.com from your Gmail"). */
  reason: string;
  /** Every value the action will use, labelled in everyday words, in order, nothing cut (spec
   *  F3). Absent from an older server: the card then labels `arguments` itself. */
  details?: ApprovalDetail[];
  /** "6d3b dfca 7bf8 cfc5": the same check code the Telegram and Slack cards for this request end
   *  with, so the owner can see two cards are the same request. */
  check_code?: string | null;
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
  /** The app a desktop.act card can be allowed in for a week ("Calendar"),
   *  offering "Allow Calendar for 7 days" beside Approve / Deny. Null or
   *  absent: the card has no weekly option. */
  weekly_app?: string | null;
  /** The account a card for a low-risk change can be allowed on for 7 days ("School Gmail"),
   *  offering "Allow low-risk changes on School Gmail for 7 days". Null or absent: no offer. */
  low_risk_account?: string | null;
  /** What the server's call checks noticed about this action (security wave), shown above the
   *  risk warning. A card with a "high" or "warn" note comes with weekly_app and
   *  low_risk_account null: it is approved once, never for a week. */
  security_notes?: SecurityNote[] | null;
}

/** How serious one security note is: "high" (danger), "warn" (warning) or "info". */
export type SecurityNoteSeverity = "high" | "warn" | "info";

/** One line a card shows about what a call check noticed: a kind for code, a severity, and one
 *  plain sentence that names hosts or addresses at most (never message text). */
export interface SecurityNote {
  kind: string;
  severity: SecurityNoteSeverity;
  text: string;
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
  /** What the skipped step would have done ("send an email"), so the chat can say so without
   *  naming the tool. Absent from an older server. */
  phrase?: string | null;
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
  /** The app the weekly button allowed, and until when. Null when the act
   *  was approved once only (no `remember`, or no usable device header). */
  weekly?: { app: string; expires_at: string } | null;
  /** The account the low-risk button allowed, and until when. Null when the card was approved
   *  once only (no `remember`, or the action no longer graded low-risk). */
  low_risk?: { account: string; expires_at: string } | null;
}

/**
 * GET /agent/app-approvals: an app Crawler may act in without a card until
 * `expires_at`, for requests from the Telegram chat or the browser it was
 * allowed from. `this_device` marks a web row allowed from this browser.
 */
export interface AppApproval {
  id: string;
  app: string;
  channel: "telegram" | "web";
  this_device: boolean;
  granted_at: string;
  expires_at: string;
  last_used_at: string | null;
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

// ---------------------------------------------------------------------------
// Connector catalog (GET /connectors/types), the OAuth broker (/oauth) and
// Slack DM linking (/connectors/{id}/slack/link).
// ---------------------------------------------------------------------------

/** How a connector can be connected, in the order the UI should prefer. */
export type ConnectorAuthKind = "oauth" | "device" | "token";

/** One credential input of a pasted-token connector. */
export interface ConnectorCredentialField {
  key: string;
  label: string;
  type: "text" | "password" | "url";
  required: boolean;
  placeholder: string;
  hint: string;
}

/** The most dangerous action category among the actions a scope unlocks. */
export type ConnectorScopeCategory = "read" | "write" | "execute" | "delete";

export interface ConnectorScopeInfo {
  scope: string;
  category: ConnectorScopeCategory;
  /** Some action behind this scope always asks before running, whatever
   * the connector's approval policy. */
  always_confirm: boolean;
  actions: string[];
}

export interface ConnectorAuthInfo {
  methods: ConnectorAuthKind[];
  fields: ConnectorCredentialField[];
  /** The OAuth broker's URL segment, or null for token-only connectors. */
  provider: string | null;
  /** The server has a client id for this provider, so "oauth" and
   * "device" can actually run. */
  oauth_configured: boolean;
  /** The auth_method to send when creating a pasted-token connector. */
  token_auth_method: AuthMethod;
  notes: string;
  /** The page where the user creates the token they paste: an https URL, or a template whose
   *  leading `{field_key}` is filled from that "url" field (connectorCatalog.tokenLink). */
  token_url?: string;
  /** That link's text (connectorCatalog.tokenLinkLabel falls back to "Get your code"). */
  token_url_label?: string;
  /** Where the server owner registers the sign-in client whose id goes in backend/.env. */
  client_setup_url?: string;
  /** The backend/.env names (never values) for that client's id and secret ("" when none). */
  client_id_setting?: string;
  client_secret_setting?: string;
}

/** One entry of GET /connectors/types (backend registry.connector_types_payload). */
export interface ConnectorTypeInfo {
  key: string;
  label: string;
  description: string;
  /** A kebab-case lucide icon name, e.g. "graduation-cap". */
  icon: string;
  docs_url: string;
  creatable: boolean;
  auth: ConnectorAuthInfo;
  scopes: { read: ConnectorScopeInfo[]; write: ConnectorScopeInfo[] };
  /** What "Allow low-risk changes" lets this connector do without asking (absent from servers
   *  that predate permission tiers). */
  low_risk?: ConnectorLowRiskAction[];
}

/** The connector a sign-in creates, or (with connector_id) reconnects. The
 * broker asks for the union of a reconnected row's scopes and these. */
export interface OAuthDraftRequest {
  display_name?: string;
  granted_scopes?: string[];
  permission_tier?: PermissionTier;
  rate_limit_per_minute?: number;
  connector_id?: string;
}

export interface OAuthStartResponse {
  flow_id: string;
  authorization_url: string;
  expires_at: string;
}

export interface OAuthDeviceResponse {
  flow_id: string;
  user_code: string;
  verification_uri: string;
  expires_at: string;
  /** Seconds between polls. */
  interval: number;
}

export type OAuthFlowState = "pending" | "complete" | "error" | "expired";

export interface OAuthFlowStatus {
  status: OAuthFlowState;
  connector_id?: string;
  error?: string;
  user_code?: string;
  verification_uri?: string;
  expires_at?: string;
  interval?: number;
}

export interface SlackLinkCode {
  code: string;
  expires_at: string;
}

export interface SlackLinkStatus {
  linked: boolean;
  team_id?: string | null;
  slack_user_id?: string | null;
  /** The DM channel for this connector's app token is connected. */
  channel_running: boolean;
  pending_code_expires_at?: string | null;
  /** The connector holds an app-level token (xapp-), which linking needs.
   * Absent from servers that predate the field. */
  has_app_token?: boolean;
}

// top10:secret_pii_redaction

// top10:file_extraction
/** A document attached to a user turn, as `Message.attachments` stores it
 *  (metadata only; the text stays on the server, encrypted). */
export interface FileAttachment {
  kind: "file";
  file_id: string;
  name: string;
  media_type: string;
  /** pdf, docx, pptx, xlsx, csv, text, markdown, html, json or image. */
  doc_kind: string;
  pages: number | null;
  chars: number;
  size_bytes: number;
  scanned_pages_unread?: number[];
}

/** What POST /api/files answers for an uploaded document. */
export interface UploadedFile {
  id: string;
  name: string;
  kind: string;
  media_type: string;
  size_bytes: number;
  pages: number | null;
  sections: number;
  chars: number;
  scanned_pages_unread: number[];
  truncated: boolean;
  warnings: string[];
  source: string;
  created_at: string;
  expires_at: string;
  /** The same file was already stored: the existing upload came back. */
  deduped?: boolean;
}

// Merged into Message above: a user turn's stored attachments (image
// metadata entries and file entries) and, client-side, the files a failed
// turn resends on Retry.
export interface Message {
  attachments?: Array<FileAttachment | { kind?: string; [key: string]: unknown }> | null;
  retry_files?: FileAttachment[];
}

// top10:scheduler_briefing

// top10:tutor_mode
/** One owner lock that forces tutor mode on (Settings ▸ Permissions ▸ Tutor locks). */
export interface TutorLock {
  id: string;
  scope: "course" | "account";
  /** null: it applies to every account on this Crawler. */
  user_id: string | null;
  /** "every account", or the account's email. */
  applies_to: string;
  /** What replies and notices call it ("MATH 221", "every account"). */
  label: string;
  canvas_course_id: string | null;
  course_code: string | null;
  course_name: string | null;
  aliases: string[];
  created_at: string;
}

export interface TutorLockList {
  /** The "Tutor mode" switch: while it is off, locks do nothing. */
  enabled: boolean;
  locks: TutorLock[];
}

export interface TutorLockCreate {
  scope: "course" | "account";
  applies_to: "all" | "me" | "email";
  email?: string;
  canvas_course_id?: string;
  course_code?: string;
  course_name?: string;
  aliases?: string[];
}

/** One of the owner's own Canvas courses, for the lock form's picker. */
export interface TutorCanvasCourse {
  id: string;
  name: string;
  course_code: string;
}

export interface TutorCanvasCourses {
  /** false: no working Canvas connector, so the course is typed instead. */
  available: boolean;
  courses: TutorCanvasCourse[];
}

/** One conversation's tutor mode (GET/PUT /agent/conversations/{id}/tutor). */
export interface ConversationTutor {
  enabled: boolean;
  mode: "off" | "on" | "locked";
  user_on: boolean;
  lock_scope: "course" | "account" | null;
  locked_by: string | null;
  off_command: string;
  /** Only on a PUT: the same reply a /tutor command gets. */
  message?: string;
}

// top10:knowledge_base

// top10:flashcards_quizzes

// top10:event_triggers

// top10:permission_tiers
/** One action "Allow low-risk changes" covers, with its short note ("star or label emails"). */
export interface ConnectorLowRiskAction {
  action: string;
  note: string;
}

/**
 * GET /agent/permission-grants: a connection whose low-risk changes run without a card until
 * `expires_at`, allowed from an approval card's "Allow low-risk changes" button. Not tied to a
 * browser or chat: it holds for every request on this account.
 */
export interface PermissionGrant {
  id: string;
  connector_id: string;
  /** The connection's label ("School Gmail") and type ("google_workspace"). */
  account: string;
  connector_type: string;
  kind: string;
  granted_from: "web" | "telegram" | "slack" | null;
  granted_at: string;
  expires_at: string;
  last_used_at: string | null;
  uses: number;
}

// top10:voice_notes

// top10:video_transcripts

// Security wave (S1): outbound message checks (Security ▸ Outgoing messages).
/** One domain the owner listed as their organisation's, install-wide. */
export interface OrganisationDomain {
  id: string;
  domain: string;
  added_at: string;
}

/** GET /security/outbound: the switch, what the sent-to history holds (counts only; it keeps
 *  fingerprints, never addresses) and the organisation's domains. */
export interface OutboundSettings {
  enabled: boolean;
  known: { addresses: number; domains: number; since: string | null };
  /** The signed-in account's own domains, which always count as the organisation's. */
  own_domains: string[];
  organisation_domains: OrganisationDomain[];
  can_edit_domains: boolean;
  domain_limit: number;
}

// Security wave (S2): scam checks on new email (Security ▸ Mail alerts).
export type MailVerdict = "likely_scam" | "suspicious" | "no_signs" | "unknown";
/** What an alert can offer behind an approval card. Only "Move to Spam/Junk" in this wave:
 *  "Block sender" is deferred (docs/BACKLOG.md, Track F row F9). */
export type MailActionKind = "move_to_spam";

/** An approval card made from an alert, and where it stands. */
export interface MailAlertCard {
  action_id: string;
  kind: MailActionKind;
  status: "pending" | "approved" | "denied" | "expired" | "missing";
  expires_at: string | null;
}

/** One flagged email: who it claims to be from, why it was flagged, and the AI review's view. */
export interface MailAlert {
  id: string;
  connector_id: string;
  account: string;
  provider: "gmail" | "outlook";
  verdict: MailVerdict;
  status: "alerted" | "quiet" | "dismissed" | "expired";
  from_name: string;
  from_address: string;
  subject: string;
  received_at: string | null;
  detected_at: string;
  reasons: string[];
  check_notes: string[];
  review: { reasons: string[]; advice: string; provider: string; model: string } | null;
  review_note: string | null;
  delivered: boolean;
  alert_note: string | null;
  cards: MailAlertCard[];
  actions: MailActionKind[];
  action_hint: string | null;
}

export interface MailAlertList {
  alerts: MailAlert[];
  next_before: string | null;
}

/** One of this account's mailboxes the scan reads. */
export interface MailScanAccount {
  connector_id: string;
  account: string;
  provider: "gmail" | "outlook";
  status: "starting" | "active" | "paused" | "error" | "no_access";
  last_checked_at: string | null;
  checked_count: number;
  flagged_count: number;
  skipped_count: number;
  last_error: string | null;
  note: string | null;
}

/** GET /security/mail/status: the switch, today's AI reviews and this account's mailboxes;
 *  `install` only for the owner. */
export interface MailScanStatus {
  enabled: boolean;
  when_off: string | null;
  ai_reviews_today: number;
  ai_reviews_per_day: number;
  link_checks: "local" | "local_and_remote";
  file_checks: "off" | "remote";
  accounts: MailScanAccount[];
  install: { accounts: number; alerts_7d: number; reviews_today: number } | null;
}

// Security wave (S3): on-demand scam checks (Security ▸ Check for scams).
export type ScamVerdict = "likely_scam" | "suspicious" | "no_signs_found" | "not_checked";

/** One link found in what was checked; `shown` is display text, never made clickable. */
export interface ScamLink {
  shown: string;
  host: string;
  looks_like: string;
  level: "malicious" | "suspicious" | "no_signs_found" | "not_checked";
  checked_by: string[];
  origin: "text" | "picture" | "qr" | "sender";
}

/** POST /security/scam-check: pasted text and up to four screenshots as data URLs. */
export interface ScamCheckRequest {
  text: string;
  note?: string;
  images: { media_type: string; data: string }[];
}

export interface ScamCheckResult {
  verdict: ScamVerdict;
  headline: string;
  /** Crawler's own fixed sentences. */
  reasons: string[];
  /** The AI provider's own reasons after filtering (no link, address or phone number), kept
   *  apart from Crawler's and shown as plain text (S3 4.6, review SEC-M2). */
  ai_reasons: string[];
  advice: string[];
  links: ScamLink[];
  notes: string[];
  qr: { present: boolean; readable: boolean };
  checked: { text_chars: number; images: number; links: number; ai: boolean };
  conversation_id: string | null;
  usage: Record<string, number>;
  provider: string;
  model: string;
  cached: boolean;
}

/** GET /security/scam-check/status: whether checks are on and what they can use right now. */
export interface ScamCheckStatus {
  effective: "on" | "off" | "blocked";
  reason: string;
  provider: string;
  sees_images: boolean;
  google_list: boolean | null;
  file_reputation: boolean | null;
  checks_per_day: number;
  checks_used_today: number;
}

// Security wave (S4): link reputation and the owner's service keys (Security ▸ Service keys).
export type SecurityServiceName = "safe_browsing" | "web_risk" | "hibp" | "virustotal";

/** One outside service a key can be saved for. Booleans only: a key is never sent back. */
export interface SecurityServiceKey {
  name: SecurityServiceName;
  label: string;
  used_for: string;
  note: string;
  console_url: string;
  key_hint: string;
  key_from_env: boolean;
  key_stored: boolean;
}

export interface SecurityServiceKeys {
  services: SecurityServiceKey[];
  /** Stored keys do not decrypt with the current ENCRYPTION_KEY: saving is refused until the
   *  owner restores the key or clears the stored secrets. */
  secrets_unreadable: boolean;
}

export interface SecurityKeyTestResult {
  ok: boolean;
  detail?: string;
  error?: string;
}

export interface LinkReputationProblem {
  kind: "key_rejected" | "rate_limited" | "timeout" | "error";
  at: string;
  http_status: number | null;
}

/** GET /security/link-reputation/status: counts, limits and the last problem; never a key,
 *  link or host. */
export interface LinkReputationStatus {
  capability: "on" | "off" | "blocked";
  reason: string;
  service: "safe_browsing" | "web_risk" | null;
  both_keys: boolean;
  lookups_last_minute: number;
  lookups_per_minute: number;
  lookups_last_day: number;
  lookups_per_day: number;
  counting_since: string;
  cache_entries: number;
  dangerous_found_last_day: number;
  not_checked_last_day: number;
  cooling_down_until: string | null;
  last_problem: LinkReputationProblem | null;
}

// Security wave (S5): MCP tool pinning (Security ▸ MCP reviews and the Connectors chip).
export type McpPinStatus = "approved" | "needs_review" | "kept_off";
export type McpReviewKind = "changed" | "new";
export type McpTrustedHow = "first_use" | "owner_test" | "owner_review";

/** A run of server text; a hidden part is shown as a labelled chip with its decoded text. */
export interface McpTextPart {
  text: string;
  hidden: boolean;
  decoded: string | null;
}

export interface McpToolPinView {
  pin_id: string;
  tool_name: string;
  remote_name: McpTextPart[];
  status: McpPinStatus;
  review_kind: McpReviewKind | null;
  removed: boolean;
  trusted_how: McpTrustedHow | null;
  hidden_characters: number;
  change_count: number;
  first_seen_at: string;
  approved_at: string | null;
  changed_at: string | null;
}

export interface McpServerReview {
  connector_id: string;
  display_name: string;
  is_active: boolean;
  needs_review_count: number;
  tools: McpToolPinView[];
}

export interface McpReviewList {
  pinning_enabled: boolean;
  servers: McpServerReview[];
}

export interface McpReviewLine {
  op: "context" | "added" | "removed" | "hunk";
  parts: McpTextPart[];
}

export interface McpToolReviewDetail {
  pin: McpToolPinView;
  connector_id: string;
  server_name: string;
  definition_hash: string;
  previous_hash: string | null;
  flags: { hidden_characters: number; looks_like_instructions: boolean; too_large: boolean };
  lines: McpReviewLine[];
  truncated: boolean;
}

/** POST /security/mcp/servers/{id}/approve: every tool approved at the hash that was shown. */
export interface McpServerApproval {
  approved: McpToolPinView[];
}

// Security wave (S6): breach monitor and the password check (Security ▸ Breach monitor).
export type BreachState = "on" | "off" | "blocked";

/** One watched address. `address` is null when it cannot be decrypted; `hint` is always set. */
export interface BreachAddress {
  id: string;
  address: string | null;
  hint: string;
  source: "account" | "added";
  status: "active" | "paused" | "error";
  readable: boolean;
  last_checked_at: string | null;
  next_check_at: string;
  baseline_at: string | null;
  breach_count: number;
  new_count: number;
  last_error_code: string | null;
  last_error: string | null;
}

export interface BreachFinding {
  id: string;
  address_id: string;
  name: string;
  title: string;
  domain: string | null;
  breach_date: string | null;
  added_at: string | null;
  pwn_count: number | null;
  data_classes: string[];
  verified: boolean;
  sensitive: boolean;
  fabricated: boolean;
  spam_list: boolean;
  baseline: boolean;
  first_seen_at: string;
  alerted_at: string | null;
  acknowledged_at: string | null;
}

/** GET /security/breach (owner only): state, watched addresses and breaches seen. */
export interface BreachOverview {
  state: BreachState;
  reason: string;
  switch_on: boolean;
  key_configured: boolean;
  check_every_days: number;
  max_addresses: number;
  account_note: string | null;
  addresses: BreachAddress[];
  findings: BreachFinding[];
  attribution: { text: string; url: string };
}

export interface BreachCheckResult {
  outcome: "checked" | "not_checked";
  address: BreachAddress;
  new_findings: BreachFinding[];
  note: string;
}

/** A Pwned Passwords range: hash suffixes for one 5-character SHA-1 prefix, with counts. */
export interface PwnedRange {
  prefix: string;
  suffixes: [string, number][];
  source: string;
}

// Security wave (S7): site rules for Crawler's browser (Security ▸ Site rules, owner only).
export type SiteRuleKind = "blocked" | "always_ask" | "trusted";

export interface SiteRule {
  id: string;
  pattern: string;
  host: string;
  include_subdomains: boolean;
  kind: SiteRuleKind;
  overrides_builtin: boolean;
  created_at: string;
  updated_at: string;
}

/** A built-in list of sensitive sites (banks, brokers, ...) and the kind the owner gave it. */
export interface SiteCategory {
  key: string;
  label: string;
  kind: SiteRuleKind;
  default_kind: SiteRuleKind;
  site_count: number;
  sites: string[];
}

export interface SiteHit {
  host: string;
  kind: "blocked" | "always_ask";
  where: "navigation" | "read" | "call" | "web";
  count: number;
  last_at: string;
}

export interface SiteRulesView {
  enabled: boolean;
  rules: SiteRule[];
  categories: SiteCategory[];
  recent: SiteHit[];
  max_rules: number;
}

export interface SiteRuleCreate {
  site: string;
  include_subdomains: boolean;
  kind: SiteRuleKind;
}

/** POST /security/site-rules/check: which rule applies to a site, explained. */
export interface SiteCheck {
  host: string;
  kind: SiteRuleKind | null;
  source: "owner" | "builtin" | null;
  category: string | null;
  rule_id: string | null;
  pattern: string | null;
  protected: boolean;
  enabled: boolean;
  explanation: string;
}

// Security wave (S9): rules on tool arguments (Security ▸ Tool rules, owner only).
export type ToolRuleOp =
  | "equals"
  | "not_equals"
  | "contains"
  | "regex"
  | "in_list"
  | "domain_in"
  | "domain_not_in"
  | "number_gt"
  | "number_lt";

/** One condition on a call's argument; `value` is a list for list ops, a number for number ops. */
export interface ToolRuleCondition {
  arg: string;
  op: ToolRuleOp;
  value: string | number | string[];
}

export interface ToolRuleDraft {
  tool: string;
  conditions: ToolRuleCondition[];
}

export interface ToolRuleCreate extends ToolRuleDraft {
  name: string;
}

export interface ToolRule extends ToolRuleCreate {
  id: string;
  summary: string;
  created_at: string;
  /** The email of the account that made the rule, or null once that account is gone. */
  created_by: string | null;
}

export interface BuiltinToolRule {
  key: string;
  name: string;
  description: string;
  enabled: boolean;
  changed_at: string | null;
}

/** An operator the form offers, and which value input it takes. */
export interface ToolRuleOperator {
  op: ToolRuleOp;
  label: string;
  value: "text" | "list" | "number" | "pattern";
}

export interface ToolRulesView {
  enabled: boolean;
  store_ok: boolean;
  builtins: BuiltinToolRule[];
  rules: ToolRule[];
  org_domains: string[];
  operators: ToolRuleOperator[];
  limits: {
    max_rules: number;
    max_conditions: number;
    max_list_items: number;
    max_value_chars: number;
    max_regex_chars: number;
    regex_text_cap: number;
  };
}

/** POST /security/tool-rules/preview: an invalid draft is `valid: false` with the reason. */
export interface ToolRulePreview {
  valid: boolean;
  error: string | null;
  summary: string;
  matches: { tool: string; category: string }[];
  reads: number;
  writes: number;
  mcp: boolean;
  truncated: boolean;
}

export interface ToolRuleCatalog {
  tools: { tool: string; category: string; args: string[] }[];
  mcp_hint: string;
}

// Security wave (S10): file reputation through VirusTotal (Security ▸ File checks).
/** Never "safe": the best a lookup says is that no engine flagged the file. */
export type FileVerdictName = "malicious" | "suspicious" | "no_detections" | "unknown";
export type FileCheckState = "queued" | "checked" | "not_checked" | "upload_pending" | "analysing";
export type FileCheckSource = "page" | "web" | "telegram" | "slack" | "gmail" | "outlook" | "hash" | "scam";

/** One of the caller's own file checks; it never carries where the bytes came from. */
export interface FileCheck {
  id: string;
  sha256: string;
  name: string;
  source: FileCheckSource;
  size_bytes: number | null;
  state: FileCheckState;
  verdict: FileVerdictName | null;
  flagged_by: number | null;
  engines: number | null;
  threat_label: string | null;
  summary: string;
  reason: string | null;
  can_upload: boolean;
  upload_needs_file: boolean;
  action_id: string | null;
  checked_at: string | null;
  updated_at: string;
}

export interface FileChecksStatus {
  state: "on" | "off" | "blocked";
  reason: string | null;
  lookups_last_24h: number;
  lookups_per_day: number;
  your_lookups_last_24h: number;
  your_lookups_per_day: number;
  upload_max_bytes: number;
}

export interface FileChecksResponse {
  service: FileChecksStatus;
  checks: FileCheck[];
}

/** POST /security/files/{id}/upload: the approval card parked for the upload (202), or the one
 *  already waiting (200, whose expiry the server does not repeat: null). */
export interface FileUploadRequest {
  action_id: string;
  expires_at: string | null;
  state: "upload_pending";
  reason: string;
}

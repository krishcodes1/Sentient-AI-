"""
SentientAI - Data Structures
============================
Secure Agentic AI Assistant Platform
CSCI-456 Senior Project — NYIT Manhattan

Covers:
  - User & Session models
  - Connector & Permission models
  - Agent Action & Approval models
  - Audit Log models
  - Threat / Security Event models
  - Dashboard / Health models
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


# ──────────────────────────────────────────────
# ENUMS
# ──────────────────────────────────────────────

class UserRole(str, Enum):
    STUDENT = "student"          # End-user: chat + approve/deny own actions
    ADMIN = "admin"              # Configure connectors, view all logs, manage users
    DEVELOPER = "developer"      # Build connectors; sandboxed; no prod data
    SECURITY_RESEARCHER = "security_researcher"  # Read-only: docs + anonymized logs


class ConnectorStatus(str, Enum):
    ACTIVE = "active"
    LIMITED = "limited"   # Connected but restricted (e.g., Robinhood crypto-only)
    OFFLINE = "offline"
    ERROR = "error"


class AuthMethod(str, Enum):
    OAUTH2 = "oauth2"
    API_KEY = "api_key"
    API_KEY_SECRET = "api_key_secret"  # key + secret pair (Robinhood)


class PermissionLevel(str, Enum):
    GRANTED = "granted"          # Auto-approved; no user prompt
    NEEDS_APPROVAL = "needs_approval"  # Requires explicit user confirm each time
    BLOCKED = "blocked"          # Permanently denied; cannot be overridden


class ApprovalMode(str, Enum):
    AUTO_APPROVE = "auto_approve"
    MANUAL_APPROVAL = "manual_approval"
    ALL_BLOCKED = "all_blocked"


class ActionStatus(str, Enum):
    APPROVED = "approved"        # Auto-approved by policy
    USER_APPROVED = "user_approved"
    AWAITING = "awaiting"        # Pending user decision
    BLOCKED = "blocked"          # Blocked by policy or threat detection
    POLICY_DENIED = "policy_denied"
    DENIED = "denied"            # User clicked Deny


class ThreatSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ThreatStatus(str, Enum):
    MITIGATED = "mitigated"
    DETECTED = "detected"
    INVESTIGATING = "investigating"


class OWASPCategory(str, Enum):
    """OWASP Top 10 for Agentic Applications (2026)"""
    PROMPT_INJECTION = "LLM01"
    INSECURE_OUTPUT_HANDLING = "LLM02"
    TRAINING_DATA_POISONING = "LLM03"
    MODEL_DENIAL_OF_SERVICE = "LLM04"
    SUPPLY_CHAIN_VULNERABILITIES = "LLM05"
    SENSITIVE_INFO_DISCLOSURE = "LLM06"
    INSECURE_PLUGIN_DESIGN = "LLM07"
    EXCESSIVE_AGENCY = "LLM08"
    OVERRELIANCE = "LLM09"
    MODEL_THEFT = "LLM10"


# ──────────────────────────────────────────────
# USER & SESSION
# ──────────────────────────────────────────────

@dataclass
class User:
    """Platform user. Stored in PostgreSQL `users` table."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    email: str = ""
    display_name: str = ""
    role: UserRole = UserRole.STUDENT
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_login: Optional[datetime] = None
    is_active: bool = True

    # Admins only — list of connector IDs this user can configure
    managed_connector_ids: List[str] = field(default_factory=list)


@dataclass
class Session:
    """Active user session. Stored in Redis for fast lookup."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None


# ──────────────────────────────────────────────
# CONNECTORS
# ──────────────────────────────────────────────

@dataclass
class OAuthCredential:
    """
    OAuth 2.0 tokens for a connector.
    Stored ENCRYPTED at rest; only decrypted in memory when needed.
    Never logged or displayed.
    """
    access_token: str = ""           # encrypted
    refresh_token: Optional[str] = None  # encrypted
    token_expiry: Optional[datetime] = None
    scopes_granted: List[str] = field(default_factory=list)
    instance_url: Optional[str] = None   # e.g. https://nyit.instructure.com


@dataclass
class APIKeyCredential:
    """API key / secret pair (e.g. Robinhood)."""
    api_key: str = ""        # encrypted
    api_secret: Optional[str] = None  # encrypted


@dataclass
class ConnectorScope:
    """
    A single permission scope on a connector (e.g. `assignments.read`).
    Maps to a badge in the Permissions UI.
    """
    name: str = ""            # e.g. "assignments.read"
    is_write: bool = False    # write scopes require explicit approval each action
    permission_level: PermissionLevel = PermissionLevel.GRANTED
    description: str = ""


@dataclass
class Connector:
    """
    A third-party integration. Each connector runs in its own Docker container.
    Stored in PostgreSQL `connectors` table.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""                    # e.g. "Canvas LMS"
    slug: str = ""                    # e.g. "canvas_lms"
    status: ConnectorStatus = ConnectorStatus.OFFLINE
    auth_method: AuthMethod = AuthMethod.OAUTH2
    approval_mode: ApprovalMode = ApprovalMode.MANUAL_APPROVAL

    # Credentials — one of these is populated
    oauth_credential: Optional[OAuthCredential] = None
    api_key_credential: Optional[APIKeyCredential] = None

    # Granted scopes (least-privilege)
    scopes: List[ConnectorScope] = field(default_factory=list)

    # Security
    content_sanitization_enabled: bool = True  # scan API responses before LLM
    docker_container_id: Optional[str] = None

    last_ping_ms: Optional[int] = None    # latency to connector health endpoint
    last_checked_at: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.utcnow)

    # For Canvas: institutional API access note
    notes: Optional[str] = None


# ──────────────────────────────────────────────
# PERMISSIONS
# ──────────────────────────────────────────────

@dataclass
class PermissionPolicy:
    """
    Per-connector permission policy for a user role.
    Stored in PostgreSQL `permission_policies` table.

    OWASP mitigations enforced here:
    - Least Privilege: only necessary scopes granted
    - Write-Action Approval: all write ops require manual confirm
    - Financial Trade Execution: hard-blocked at platform level
    - Excessive Agency Prevention: agent cannot self-modify permissions
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    connector_id: str = ""
    role: UserRole = UserRole.STUDENT
    approval_mode: ApprovalMode = ApprovalMode.MANUAL_APPROVAL

    # Scope-level overrides (scope name → PermissionLevel)
    scope_overrides: Dict[str, PermissionLevel] = field(default_factory=dict)

    # Hard-blocked actions that CANNOT be overridden by any user or admin.
    # e.g. {"robinhood": ["trade.execute", "orders.place"]}
    platform_blocked_actions: List[str] = field(default_factory=list)

    updated_at: datetime = field(default_factory=datetime.utcnow)
    updated_by: Optional[str] = None   # user_id of admin who last saved


# ──────────────────────────────────────────────
# AGENT ACTIONS & APPROVAL QUEUE
# ──────────────────────────────────────────────

@dataclass
class AgentAction:
    """
    A single action the agent wants to perform via a connector.
    Every action is checked against PermissionPolicy before execution.
    Immutably written to AuditLog after resolution.

    Stored in PostgreSQL `agent_actions` table.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str = ""
    user_id: str = ""
    connector_id: str = ""
    connector_name: str = ""     # denormalized for display

    # What the agent is trying to do
    http_method: str = ""        # GET / POST / PUT / DELETE
    api_endpoint: str = ""       # e.g. /api/v1/courses/12345/assignments
    scope_required: str = ""     # e.g. "assignments.read"
    is_write_operation: bool = False

    # Human-readable description surfaced in approval UI
    description: str = ""        # e.g. "Create event: CS101 Study Session"
    data_involved: Optional[Dict[str, Any]] = None

    # Agent reasoning chain (shown in audit log detail panel)
    reasoning: Optional[str] = None
    triggered_by: Optional[str] = None  # e.g. user message that caused this

    status: ActionStatus = ActionStatus.AWAITING
    threat_detected: bool = False
    threat_event_id: Optional[str] = None  # FK → ThreatEvent

    requested_at: datetime = field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[str] = None     # "auto_policy" | user_id


@dataclass
class ApprovalRequest:
    """
    Shown in the Agent Chat approval card UI when the agent needs explicit consent.
    One ApprovalRequest per AgentAction that requires NEEDS_APPROVAL.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    action_id: str = ""
    user_id: str = ""

    # UI card fields
    connector_name: str = ""
    connector_scope: str = ""    # shown in monospace e.g. "calendar.write"
    human_description: str = ""  # e.g. 'Create event: "CS101 Study Session" on Wed Mar 26'
    is_write_operation: bool = True

    is_resolved: bool = False
    approved: Optional[bool] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None


# ──────────────────────────────────────────────
# AUDIT LOGS
# ──────────────────────────────────────────────

@dataclass
class AuditLogEntry:
    """
    Immutable record of every agent action and data access event.
    Tamper-evident: each entry stores SHA-256 of its own content + previous hash.

    Stored in PostgreSQL `audit_log` table with append-only policy.
    OWASP: Immutable Audit Trail (SHA-256 hash-chained for all actions).
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    action_id: str = ""
    user_id: str = ""
    session_id: str = ""

    timestamp: datetime = field(default_factory=datetime.utcnow)
    connector: str = ""           # connector slug
    http_method: str = ""
    api_endpoint: str = ""
    scope: str = ""               # the scope badge shown in Audit Log UI
    status: ActionStatus = ActionStatus.APPROVED

    # Security detail
    threat_detected: bool = False
    block_reason: Optional[str] = None
    detection_layer: Optional[str] = None  # "pattern_match" | "ai_classifier" | "policy"
    detection_confidence: Optional[float] = None  # 0.0 – 1.0

    # Tamper-evidence
    content_hash: str = ""        # SHA-256 of this entry's fields (computed on write)
    previous_hash: str = ""       # SHA-256 of the previous entry (chain)
    chain_index: int = 0          # monotonically increasing

    def compute_hash(self) -> str:
        payload = {
            "id": self.id,
            "action_id": self.action_id,
            "user_id": self.user_id,
            "timestamp": self.timestamp.isoformat(),
            "connector": self.connector,
            "http_method": self.http_method,
            "api_endpoint": self.api_endpoint,
            "scope": self.scope,
            "status": self.status,
            "previous_hash": self.previous_hash,
            "chain_index": self.chain_index,
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()

    def seal(self) -> None:
        """Call before writing to DB. Sets content_hash."""
        self.content_hash = self.compute_hash()

    def verify(self) -> bool:
        """Returns True if the entry has not been tampered with."""
        return self.content_hash == self.compute_hash()


# ──────────────────────────────────────────────
# THREAT / SECURITY EVENTS
# ──────────────────────────────────────────────

@dataclass
class ThreatEvent:
    """
    A security event detected by the Prompt Injection Defense pipeline
    or the Permission Engine.

    Shown in Threat Monitor → Live Threat Feed.
    Stored in PostgreSQL `threat_events` table.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    action_id: Optional[str] = None    # FK → AgentAction (if applicable)
    connector_id: Optional[str] = None

    owasp_category: OWASPCategory = OWASPCategory.PROMPT_INJECTION
    severity: ThreatSeverity = ThreatSeverity.MEDIUM
    status: ThreatStatus = ThreatStatus.MITIGATED

    title: str = ""               # e.g. "Prompt Injection"
    description: str = ""        # e.g. "Hidden instruction in Canvas API response attempting to override system prompt."
    source: Optional[str] = None  # e.g. URL or API endpoint where threat was found

    detected_at: datetime = field(default_factory=datetime.utcnow)
    mitigated_at: Optional[datetime] = None

    # Detection pipeline detail
    detection_layer: str = ""     # "pattern_match" | "ai_classifier" | "permission_engine"
    confidence: Optional[float] = None


@dataclass
class OWASPComplianceSummary:
    """
    Snapshot of compliance posture shown at the bottom of the Permissions screen.
    Computed at request time from current policy configuration.
    """
    least_privilege_enforced: bool = False
    write_action_approval_required: bool = False
    financial_trade_execution_blocked: bool = False
    prompt_injection_detection_enabled: bool = False
    immutable_audit_trail_enabled: bool = False
    excessive_agency_prevention_enabled: bool = False

    computed_at: datetime = field(default_factory=datetime.utcnow)


# ──────────────────────────────────────────────
# DASHBOARD / SYSTEM HEALTH
# ──────────────────────────────────────────────

@dataclass
class ConnectorHealthStatus:
    """One row in the Dashboard → Connector Health panel."""
    connector_id: str = ""
    connector_name: str = ""
    status: ConnectorStatus = ConnectorStatus.OFFLINE
    ping_ms: Optional[int] = None


@dataclass
class LiveAgentActivityItem:
    """One row in the Dashboard → Live Agent Activity feed."""
    action_id: str = ""
    connector_name: str = ""
    action_summary: str = ""          # e.g. "Fetched assignment list"
    api_endpoint: str = ""
    status: ActionStatus = ActionStatus.APPROVED
    timestamp: datetime = field(default_factory=datetime.utcnow)
    minutes_ago: int = 0


@dataclass
class DashboardSummary:
    """
    Real-time snapshot for the main Dashboard screen.
    Polled from the backend every N seconds by the React frontend.
    """
    active_connectors: int = 0
    healthy_connectors: int = 0
    agent_actions_24h: int = 0
    agent_actions_24h_delta_pct: float = 0.0   # % change vs yesterday
    blocked_threats_24h: int = 0
    pending_approvals: int = 0

    live_activity: List[LiveAgentActivityItem] = field(default_factory=list)
    connector_health: List[ConnectorHealthStatus] = field(default_factory=list)

    # Security Events chart data — list of (date_label, approved_count, blocked_count)
    security_events_7d: List[Dict[str, Any]] = field(default_factory=list)

    generated_at: datetime = field(default_factory=datetime.utcnow)


# ──────────────────────────────────────────────
# AGENT CHAT
# ──────────────────────────────────────────────

class MessageRole(str, Enum):
    USER = "user"
    ASSISTANT = "assistant"
    SYSTEM = "system"


@dataclass
class ChatMessage:
    """One turn in the Agent Chat conversation."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str = ""
    role: MessageRole = MessageRole.USER
    content: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)

    # If this message contains an approval card
    approval_request_id: Optional[str] = None

    # Tool calls made during this assistant turn
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ChatSession:
    """
    A conversation session between the user and the agent.
    Linked to AgentActions triggered during the conversation.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str = ""
    title: Optional[str] = None         # auto-generated from first user message
    messages: List[ChatMessage] = field(default_factory=list)
    active_connector_ids: List[str] = field(default_factory=list)
    prompt_shield_active: bool = True   # always-on in production
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_active_at: datetime = field(default_factory=datetime.utcnow)


# ──────────────────────────────────────────────
# PROMPT INJECTION DETECTION PIPELINE
# ──────────────────────────────────────────────

@dataclass
class SanitizationResult:
    """
    Output of the two-layer prompt injection detection pipeline
    run on all external content (API responses, web pages, emails)
    BEFORE the LLM processes them.

    Layer 1: Pattern matching (known attack signatures)
    Layer 2: AI classifier (subtle / novel attacks)
    """
    input_source: str = ""              # connector + endpoint that produced the content
    content_hash: str = ""             # SHA-256 of original content

    # Layer 1
    pattern_match_triggered: bool = False
    pattern_match_signatures: List[str] = field(default_factory=list)

    # Layer 2
    ai_classifier_triggered: bool = False
    ai_classifier_confidence: float = 0.0

    # Combined decision
    is_safe: bool = True
    threat_event_id: Optional[str] = None  # set if blocked
    checked_at: datetime = field(default_factory=datetime.utcnow)


# ──────────────────────────────────────────────
# QUICK REFERENCE — DATABASE TABLE MAPPING
# ──────────────────────────────────────────────
#
#  Class                  → PostgreSQL table
#  ─────────────────────────────────────────────
#  User                   → users
#  Session                → sessions               (also cached in Redis)
#  Connector              → connectors
#  OAuthCredential        → connector_credentials  (encrypted columns)
#  APIKeyCredential       → connector_credentials  (encrypted columns)
#  ConnectorScope         → connector_scopes
#  PermissionPolicy       → permission_policies
#  AgentAction            → agent_actions
#  ApprovalRequest        → approval_requests
#  AuditLogEntry          → audit_log              (append-only, hash-chained)
#  ThreatEvent            → threat_events
#  SanitizationResult     → sanitization_results
#  ChatSession            → chat_sessions
#  ChatMessage            → chat_messages
#
#  DashboardSummary       → computed at request time (not persisted)
#  OWASPComplianceSummary → computed at request time (not persisted)

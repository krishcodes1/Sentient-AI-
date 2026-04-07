"""
SentientAI - Data Structures and Methods
CSCI-456 Senior Project | NYIT Manhattan Campus
Team: Krish Schroff, Rafi Hossain, Miadul Haque, Edrich Silva
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


# ==============================================================================
# ENUMS
# ==============================================================================

class PermissionTier(Enum):
    """
    The four-tier permission model that controls every agent action.
    - AUTO_APPROVE: low-risk reads (e.g., fetch assignment list)
    - USER_CONFIRM: medium-risk writes (e.g., compose email draft)
    - ADMIN_ONLY:   sensitive configuration changes
    - HARD_BLOCKED: permanently forbidden (e.g., executing financial trades)
    """
    AUTO_APPROVE = "auto_approve"
    USER_CONFIRM = "user_confirm"
    ADMIN_ONLY   = "admin_only"
    HARD_BLOCKED = "hard_blocked"


class ActionStatus(Enum):
    """Lifecycle state of a single agent action."""
    PENDING          = "pending"          # Submitted, not yet evaluated
    APPROVED         = "approved"         # Permission check passed / user approved
    AWAITING_APPROVAL = "awaiting_approval"  # Waiting for human decision
    BLOCKED          = "blocked"          # Stopped by permission engine or injection guard
    COMPLETED        = "completed"        # Successfully executed
    FAILED           = "failed"           # Execution attempted but errored


class ConnectorStatus(Enum):
    """Health state of a third-party service connector."""
    CONNECTED     = "connected"
    DISCONNECTED  = "disconnected"
    LIMITED_ACCESS = "limited_access"
    ERROR         = "error"


class ConnectorType(Enum):
    """Supported external service connectors."""
    CANVAS     = "canvas"
    GMAIL      = "gmail"
    GOOGLE_CALENDAR = "google_calendar"
    ROBINHOOD  = "robinhood"
    FILE_SYSTEM = "file_system"
    POSTGRESQL = "postgresql"


class ThreatType(Enum):
    """Categories of detected security events."""
    PROMPT_INJECTION   = "prompt_injection"
    PERMISSION_BYPASS  = "permission_bypass"
    CREDENTIAL_LEAK    = "credential_leak"
    ANOMALOUS_BEHAVIOR = "anomalous_behavior"
    RATE_LIMIT_ABUSE   = "rate_limit_abuse"


class UserRole(Enum):
    """Platform roles with escalating access."""
    STUDENT    = "student"       # End user — chat + approve/deny only
    ADMIN      = "admin"         # Configures connectors and policies
    DEVELOPER  = "developer"     # Builds connectors in sandboxed env
    RESEARCHER = "researcher"    # Read-only access to architecture/logs


class InjectionDetectionLayer(Enum):
    """Which layer of the pipeline caught a threat."""
    PATTERN_SANITIZER = "pattern_sanitizer"   # Deterministic regex / blocklist
    LLM_CLASSIFIER    = "llm_classifier"      # Small AI model second opinion
    PERMISSION_ENGINE = "permission_engine"   # Last-resort action block


# ==============================================================================
# USERS
# ==============================================================================

@dataclass
class User:
    """
    A platform user account.

    Attributes:
        user_id     : Globally unique identifier (UUID4).
        username    : Display / login name.
        email       : Contact email.
        role        : Access level (see UserRole).
        created_at  : ISO-8601 creation timestamp.
        is_active   : Soft-delete / suspension flag.
    """
    user_id:    str = field(default_factory=lambda: str(uuid.uuid4()))
    username:   str = ""
    email:      str = ""
    role:       UserRole = UserRole.STUDENT
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    is_active:  bool = True

    # ------------------------------------------------------------------
    # Methods
    # ------------------------------------------------------------------

    def is_admin(self) -> bool:
        """Return True if the user holds admin or higher privileges."""
        return self.role in (UserRole.ADMIN,)

    def can_approve_actions(self) -> bool:
        """Students and admins may approve/deny agent actions."""
        return self.role in (UserRole.STUDENT, UserRole.ADMIN)

    def can_configure_connectors(self) -> bool:
        """Only admins may add or modify connector configurations."""
        return self.role == UserRole.ADMIN

    def to_dict(self) -> dict:
        """Serialize the user to a JSON-safe dict (e.g. for API responses)."""
        return {
            "user_id":    self.user_id,
            "username":   self.username,
            "email":      self.email,
            "role":       self.role.value,        # Enum → plain string for serialisation
            "created_at": self.created_at,
            "is_active":  self.is_active,
        }


# ==============================================================================
# PERMISSIONS
# ==============================================================================

@dataclass
class PermissionPolicy:
    """
    Maps a (connector, action_type) pair to a PermissionTier.

    Example:
        PermissionPolicy(
            connector_type=ConnectorType.GMAIL,
            action_type="send_email",
            tier=PermissionTier.USER_CONFIRM,
        )
    """
    policy_id:      str = field(default_factory=lambda: str(uuid.uuid4()))
    connector_type: ConnectorType = ConnectorType.CANVAS
    action_type:    str = ""          # e.g. "read_assignments", "send_email"
    tier:           PermissionTier = PermissionTier.AUTO_APPROVE
    description:    str = ""
    created_by:     str = ""          # admin user_id
    created_at:     str = field(default_factory=lambda: datetime.utcnow().isoformat())

    # ------------------------------------------------------------------
    # Methods
    # ------------------------------------------------------------------

    def is_blocked(self) -> bool:
        """Return True if this action is permanently forbidden (HARD_BLOCKED tier)."""
        return self.tier == PermissionTier.HARD_BLOCKED

    def requires_human(self) -> bool:
        """Return True if a human must approve this action before it can execute."""
        return self.tier in (PermissionTier.USER_CONFIRM, PermissionTier.ADMIN_ONLY)

    def to_dict(self) -> dict:
        """Serialize to a JSON-safe dict, omitting internal fields like created_by."""
        return {
            "policy_id":      self.policy_id,
            "connector_type": self.connector_type.value,
            "action_type":    self.action_type,
            "tier":           self.tier.value,
            "description":    self.description,
        }


@dataclass
class PermissionEngine:
    """
    Central authority that evaluates every proposed agent action.

    The engine holds a registry of PermissionPolicy objects.
    Unknown action types default to HARD_BLOCKED (deny-by-default).
    """
    policies: list[PermissionPolicy] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Methods
    # ------------------------------------------------------------------

    def add_policy(self, policy: PermissionPolicy) -> None:
        """Register a new permission policy."""
        self.policies.append(policy)

    def evaluate(self, connector_type: ConnectorType, action_type: str) -> PermissionTier:
        """
        Look up the tier for a given connector + action pair.
        Returns HARD_BLOCKED if no matching policy exists (deny-by-default).
        """
        for policy in self.policies:
            if policy.connector_type == connector_type and policy.action_type == action_type:
                return policy.tier
        return PermissionTier.HARD_BLOCKED   # Unknown action → block

    def is_action_allowed(self, connector_type: ConnectorType, action_type: str) -> bool:
        """Quick boolean — True if the action is NOT hard-blocked."""
        return self.evaluate(connector_type, action_type) != PermissionTier.HARD_BLOCKED

    def get_policies_for_connector(self, connector_type: ConnectorType) -> list[PermissionPolicy]:
        """Return all policies scoped to a specific connector."""
        return [p for p in self.policies if p.connector_type == connector_type]


# ==============================================================================
# CONNECTORS
# ==============================================================================

@dataclass
class ConnectorScope:
    """
    Declares the exact OAuth scopes a connector requests.
    Principle of least privilege: request only what is needed.
    """
    scope_id:       str = field(default_factory=lambda: str(uuid.uuid4()))
    connector_type: ConnectorType = ConnectorType.CANVAS
    scopes:         list[str] = field(default_factory=list)  # e.g. ["gmail.readonly"]
    is_read_only:   bool = True

    def to_dict(self) -> dict:
        return {
            "connector_type": self.connector_type.value,
            "scopes":         self.scopes,
            "is_read_only":   self.is_read_only,
        }


@dataclass
class ConnectorCredential:
    """
    Encrypted storage record for OAuth tokens and API keys.
    Raw token values are NEVER written to logs or returned in API responses.
    """
    credential_id:       str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id:             str = ""
    connector_type:      ConnectorType = ConnectorType.CANVAS
    encrypted_token:     str = ""   # AES-256-GCM ciphertext (base64)
    token_expiry:        Optional[str] = None  # ISO-8601
    refresh_token_hash:  str = ""   # SHA-256 of refresh token, never plaintext
    created_at:          str = field(default_factory=lambda: datetime.utcnow().isoformat())
    last_refreshed_at:   Optional[str] = None

    # ------------------------------------------------------------------
    # Methods
    # ------------------------------------------------------------------

    def is_expired(self) -> bool:
        """Return True if the access token has passed its expiry timestamp."""
        if not self.token_expiry:
            return False
        return datetime.utcnow().isoformat() > self.token_expiry

    def needs_refresh(self) -> bool:
        """Return True if the token is expired but a refresh token is available to renew it."""
        return self.is_expired() and bool(self.refresh_token_hash)

    def to_safe_dict(self) -> dict:
        """Return a representation safe to display in the UI (no secrets)."""
        return {
            "credential_id":     self.credential_id,
            "connector_type":    self.connector_type.value,
            "token_expiry":      self.token_expiry,
            "last_refreshed_at": self.last_refreshed_at,
            "is_expired":        self.is_expired(),
        }


@dataclass
class Connector:
    """
    Runtime state of a third-party service connector.
    Each connector runs in its own Docker container (isolated execution).
    """
    connector_id:     str = field(default_factory=lambda: str(uuid.uuid4()))
    connector_type:   ConnectorType = ConnectorType.CANVAS
    user_id:          str = ""
    status:           ConnectorStatus = ConnectorStatus.DISCONNECTED
    scope:            Optional[ConnectorScope] = None
    credential_id:    Optional[str] = None   # FK → ConnectorCredential
    container_id:     Optional[str] = None   # Docker container ID
    last_used_at:     Optional[str] = None
    error_message:    Optional[str] = None
    created_at:       str = field(default_factory=lambda: datetime.utcnow().isoformat())

    # ------------------------------------------------------------------
    # Methods
    # ------------------------------------------------------------------

    def is_healthy(self) -> bool:
        """Return True only when the connector is fully connected and ready to serve requests."""
        return self.status == ConnectorStatus.CONNECTED

    def mark_connected(self, container_id: str) -> None:
        """Transition to CONNECTED state once the Docker container is confirmed running."""
        self.status = ConnectorStatus.CONNECTED
        self.container_id = container_id
        self.error_message = None   # Clear any prior error on successful reconnect

    def mark_error(self, message: str) -> None:
        """Record an error state; the message is surfaced to admins in the dashboard."""
        self.status = ConnectorStatus.ERROR
        self.error_message = message

    def record_usage(self) -> None:
        """Stamp the current UTC time as the last-used timestamp for activity tracking."""
        self.last_used_at = datetime.utcnow().isoformat()

    def to_dict(self) -> dict:
        """Serialize connector state for API responses; excludes the Docker container ID."""
        return {
            "connector_id":   self.connector_id,
            "connector_type": self.connector_type.value,
            "status":         self.status.value,
            "last_used_at":   self.last_used_at,
            "error_message":  self.error_message,
        }


# ==============================================================================
# AGENT ACTIONS
# ==============================================================================

@dataclass
class AgentAction:
    """
    A single atomic step the agent wants to take.

    Every action is evaluated by the PermissionEngine before execution.
    The full lifecycle is captured here for audit purposes.
    """
    action_id:        str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id:       str = ""          # Parent chat session
    user_id:          str = ""
    connector_type:   ConnectorType = ConnectorType.CANVAS
    action_type:      str = ""          # e.g. "read_assignments"
    parameters:       dict = field(default_factory=dict)  # Action-specific args
    permission_tier:  Optional[PermissionTier] = None     # Set by PermissionEngine
    status:           ActionStatus = ActionStatus.PENDING
    reasoning:        str = ""          # Agent's explanation of why it chose this action
    result:           Optional[Any] = None
    error:            Optional[str] = None
    requested_at:     str = field(default_factory=lambda: datetime.utcnow().isoformat())
    resolved_at:      Optional[str] = None
    approved_by:      Optional[str] = None   # user_id of approver, if applicable

    # ------------------------------------------------------------------
    # Methods
    # ------------------------------------------------------------------

    def approve(self, approver_id: str) -> None:
        """Human approves the pending action."""
        self.status = ActionStatus.APPROVED
        self.approved_by = approver_id
        self.resolved_at = datetime.utcnow().isoformat()

    def block(self, reason: str) -> None:
        """Permission engine or injection guard blocks the action."""
        self.status = ActionStatus.BLOCKED
        self.error = reason
        self.resolved_at = datetime.utcnow().isoformat()

    def complete(self, result: Any) -> None:
        """Mark the action as successfully executed with its result."""
        self.status = ActionStatus.COMPLETED
        self.result = result
        self.resolved_at = datetime.utcnow().isoformat()

    def fail(self, error: str) -> None:
        """Mark the action as failed during execution."""
        self.status = ActionStatus.FAILED
        self.error = error
        self.resolved_at = datetime.utcnow().isoformat()

    def to_dict(self) -> dict:
        """
        Serialize the action for audit logs and API responses.
        Note: `result` and `error` are intentionally excluded here; they are
        captured in the AuditLogEntry.details field to keep this payload lean.
        """
        return {
            "action_id":       self.action_id,
            "connector_type":  self.connector_type.value,
            "action_type":     self.action_type,
            "parameters":      self.parameters,
            "permission_tier": self.permission_tier.value if self.permission_tier else None,
            "status":          self.status.value,
            "reasoning":       self.reasoning,
            "requested_at":    self.requested_at,
            "resolved_at":     self.resolved_at,
            "approved_by":     self.approved_by,
        }


# ==============================================================================
# SECURITY / INJECTION DETECTION
# ==============================================================================

@dataclass
class InjectionScanResult:
    """
    Output of the two-layer prompt injection detection pipeline.

    Layer 1 — Pattern Sanitizer: deterministic blocklist/regex scan.
    Layer 2 — LLM Classifier:    small AI model evaluates content intent.
    """
    scan_id:          str = field(default_factory=lambda: str(uuid.uuid4()))
    action_id:        str = ""
    content_snippet:  str = ""      # First 200 chars of scanned content (for logs)
    is_threat:        bool = False
    threat_type:      Optional[ThreatType] = None
    detected_by:      Optional[InjectionDetectionLayer] = None
    confidence:       float = 0.0   # 0.0 – 1.0, meaningful only for LLM layer
    patterns_matched: list[str] = field(default_factory=list)   # Layer 1 hits
    scanned_at:       str = field(default_factory=lambda: datetime.utcnow().isoformat())

    # ------------------------------------------------------------------
    # Methods
    # ------------------------------------------------------------------

    def flag_as_threat(
        self,
        threat_type: ThreatType,
        layer: InjectionDetectionLayer,
        confidence: float = 1.0,
        patterns: Optional[list[str]] = None,
    ) -> None:
        """
        Mark this scan result as a detected threat.

        Args:
            threat_type : Category of the threat (e.g. PROMPT_INJECTION).
            layer       : Which pipeline layer made the detection.
            confidence  : Detection confidence in [0.0, 1.0]; defaults to 1.0
                          for deterministic (Layer 1) hits.
            patterns    : Regex / blocklist patterns that matched (Layer 1 only).
        """
        self.is_threat = True
        self.threat_type = threat_type
        self.detected_by = layer
        self.confidence = confidence
        self.patterns_matched = patterns or []   # Avoid mutable default argument

    def to_dict(self) -> dict:
        return {
            "scan_id":          self.scan_id,
            "action_id":        self.action_id,
            "is_threat":        self.is_threat,
            "threat_type":      self.threat_type.value if self.threat_type else None,
            "detected_by":      self.detected_by.value if self.detected_by else None,
            "confidence":       self.confidence,
            "patterns_matched": self.patterns_matched,
            "scanned_at":       self.scanned_at,
        }


@dataclass
class SecurityEvent:
    """
    A recorded security incident — threat detected, policy violated, etc.
    Feeds the Threat Monitor panel on the dashboard.
    """
    event_id:     str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id:      str = ""
    action_id:    Optional[str] = None
    threat_type:  ThreatType = ThreatType.PROMPT_INJECTION
    description:  str = ""
    severity:     str = "medium"   # "low" | "medium" | "high" | "critical"
    resolved:     bool = False
    occurred_at:  str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def resolve(self) -> None:
        """Mark the security event as resolved (e.g. after admin review)."""
        self.resolved = True

    def to_dict(self) -> dict:
        return {
            "event_id":    self.event_id,
            "threat_type": self.threat_type.value,
            "description": self.description,
            "severity":    self.severity,
            "resolved":    self.resolved,
            "occurred_at": self.occurred_at,
        }


# ==============================================================================
# AUDIT LOG
# ==============================================================================

@dataclass
class AuditLogEntry:
    """
    Immutable, tamper-evident record of a single platform event.

    Each entry carries a SHA-256 integrity hash computed at write time.
    The application layer provides no UPDATE or DELETE path for this table —
    rows are append-only.  A verification utility can walk the log and
    confirm every entry's hash is still valid.
    """
    log_id:        str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id:       str = ""
    action_id:     Optional[str] = None
    event_type:    str = ""         # "permission_check" | "connector_call" | "action_blocked" …
    connector_type: Optional[str] = None
    action_type:   Optional[str] = None
    status:        str = ""
    details:       dict = field(default_factory=dict)
    integrity_hash: str = ""        # SHA-256 of the serialised entry (set on creation)
    logged_at:     str = field(default_factory=lambda: datetime.utcnow().isoformat())

    # ------------------------------------------------------------------
    # Methods
    # ------------------------------------------------------------------

    def compute_hash(self) -> str:
        """
        Compute and store the SHA-256 integrity hash for this entry.
        Call once immediately after setting all fields.
        """
        payload = json.dumps({
            "log_id":        self.log_id,
            "user_id":       self.user_id,
            "action_id":     self.action_id,
            "event_type":    self.event_type,
            "connector_type": self.connector_type,
            "action_type":   self.action_type,
            "status":        self.status,
            "details":       self.details,
            "logged_at":     self.logged_at,
        }, sort_keys=True)
        self.integrity_hash = hashlib.sha256(payload.encode()).hexdigest()
        return self.integrity_hash

    def verify_integrity(self) -> bool:
        """
        Recompute the hash and compare to the stored value.
        Returns False if the entry has been tampered with.
        """
        stored = self.integrity_hash
        recomputed = self.compute_hash()
        return stored == recomputed

    def to_dict(self) -> dict:
        return {
            "log_id":         self.log_id,
            "user_id":        self.user_id,
            "action_id":      self.action_id,
            "event_type":     self.event_type,
            "connector_type": self.connector_type,
            "action_type":    self.action_type,
            "status":         self.status,
            "details":        self.details,
            "integrity_hash": self.integrity_hash,
            "logged_at":      self.logged_at,
        }


@dataclass
class AuditLog:
    """
    In-memory audit log store (backed by PostgreSQL in production).
    Provides append, query, and bulk integrity-verification methods.
    """
    entries: list[AuditLogEntry] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Methods
    # ------------------------------------------------------------------

    def append(self, entry: AuditLogEntry) -> None:
        """Hash and append a new entry. No updates or deletes allowed."""
        entry.compute_hash()
        self.entries.append(entry)

    def verify_all(self) -> dict[str, bool]:
        """
        Walk every entry and verify its integrity hash.
        Returns a dict mapping log_id → is_valid.
        """
        return {e.log_id: e.verify_integrity() for e in self.entries}

    def query(
        self,
        user_id: Optional[str] = None,
        connector_type: Optional[str] = None,
        status: Optional[str] = None,
        event_type: Optional[str] = None,
        since: Optional[str] = None,
    ) -> list[AuditLogEntry]:
        """Filter entries by one or more optional criteria."""
        results = self.entries
        if user_id:
            results = [e for e in results if e.user_id == user_id]
        if connector_type:
            results = [e for e in results if e.connector_type == connector_type]
        if status:
            results = [e for e in results if e.status == status]
        if event_type:
            results = [e for e in results if e.event_type == event_type]
        if since:
            # ISO-8601 strings are lexicographically sortable, so string
            # comparison is equivalent to chronological comparison here.
            results = [e for e in results if e.logged_at >= since]
        return results

    def count_by_status(self) -> dict[str, int]:
        """Return a tally of entries grouped by status (for dashboard charts)."""
        tally: dict[str, int] = {}
        for entry in self.entries:
            tally[entry.status] = tally.get(entry.status, 0) + 1
        return tally


# ==============================================================================
# CHAT SESSION & MESSAGES
# ==============================================================================

@dataclass
class ChatMessage:
    """A single message within a conversation session."""
    message_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str = ""
    role:       str = "user"     # "user" | "assistant" | "system"
    content:    str = ""
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict:
        """Serialize to the format expected by the LLM API message history."""
        return {
            "message_id": self.message_id,
            "role":       self.role,
            "content":    self.content,
            "created_at": self.created_at,
        }


@dataclass
class ChatSession:
    """
    Represents one conversation between a user and the agent.
    Maintains full message history (required for multi-turn context).
    """
    session_id:  str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id:     str = ""
    messages:    list[ChatMessage] = field(default_factory=list)
    actions:     list[AgentAction] = field(default_factory=list)
    is_active:   bool = True
    created_at:  str = field(default_factory=lambda: datetime.utcnow().isoformat())
    ended_at:    Optional[str] = None

    # ------------------------------------------------------------------
    # Methods
    # ------------------------------------------------------------------

    def add_message(self, role: str, content: str) -> ChatMessage:
        """Append a new message and return it."""
        msg = ChatMessage(session_id=self.session_id, role=role, content=content)
        self.messages.append(msg)
        return msg

    def add_action(self, action: AgentAction) -> None:
        """Attach an action to this session and backfill its session_id foreign key."""
        action.session_id = self.session_id
        self.actions.append(action)

    def get_history(self) -> list[dict]:
        """Return messages in the format expected by the LLM API."""
        return [{"role": m.role, "content": m.content} for m in self.messages]

    def end(self) -> None:
        """Close the session and record the termination timestamp."""
        self.is_active = False
        self.ended_at = datetime.utcnow().isoformat()

    def pending_approvals(self) -> list[AgentAction]:
        """Return actions currently waiting for human review."""
        return [a for a in self.actions if a.status == ActionStatus.AWAITING_APPROVAL]

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "user_id":    self.user_id,
            "is_active":  self.is_active,
            "created_at": self.created_at,
            "messages":   [m.to_dict() for m in self.messages],
        }


# ==============================================================================
# AGENT RUNTIME
# ==============================================================================

@dataclass
class AgentRuntime:
    """
    Orchestrates the full request → permission check → connector → response cycle.

    The runtime never executes a tool call directly.
    Every proposed action is routed through the PermissionEngine first.
    """
    runtime_id:        str = field(default_factory=lambda: str(uuid.uuid4()))
    permission_engine: PermissionEngine = field(default_factory=PermissionEngine)
    audit_log:         AuditLog = field(default_factory=AuditLog)
    connectors:        dict[str, Connector] = field(default_factory=dict)  # connector_id → Connector
    active_sessions:   dict[str, ChatSession] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def create_session(self, user_id: str) -> ChatSession:
        """Instantiate a new ChatSession for the given user and register it."""
        session = ChatSession(user_id=user_id)
        self.active_sessions[session.session_id] = session
        return session

    def get_session(self, session_id: str) -> Optional[ChatSession]:
        """Look up an active session by ID; returns None if not found."""
        return self.active_sessions.get(session_id)

    def end_session(self, session_id: str) -> None:
        """Remove a session from the active registry and mark it as ended."""
        session = self.active_sessions.pop(session_id, None)
        if session:
            session.end()

    # ------------------------------------------------------------------
    # Connector management
    # ------------------------------------------------------------------

    def register_connector(self, connector: Connector) -> None:
        """Add a connector to the runtime registry, keyed by its unique ID."""
        self.connectors[connector.connector_id] = connector

    def get_connector(self, connector_type: ConnectorType, user_id: str) -> Optional[Connector]:
        """Find the first connector matching both type and owner; returns None if not found."""
        for c in self.connectors.values():
            if c.connector_type == connector_type and c.user_id == user_id:
                return c
        return None

    def get_healthy_connectors(self) -> list[Connector]:
        """Return all connectors currently in the CONNECTED state."""
        return [c for c in self.connectors.values() if c.is_healthy()]

    # ------------------------------------------------------------------
    # Action lifecycle
    # ------------------------------------------------------------------

    def propose_action(self, action: AgentAction) -> ActionStatus:
        """
        Evaluate a proposed action against the permission engine.
        Logs the decision and updates the action's status.
        Returns the resulting ActionStatus.
        """
        # Resolve the permission tier for this connector + action combination.
        tier = self.permission_engine.evaluate(action.connector_type, action.action_type)
        action.permission_tier = tier

        if tier == PermissionTier.HARD_BLOCKED:
            # Permanently forbidden — block immediately, no human escalation.
            action.block("Action is permanently blocked by platform policy.")
            self._log_action(action, "action_blocked")
            return ActionStatus.BLOCKED

        if tier == PermissionTier.AUTO_APPROVE:
            # Low-risk read — proceed without user interaction.
            action.status = ActionStatus.APPROVED
            self._log_action(action, "action_auto_approved")
            return ActionStatus.APPROVED

        # USER_CONFIRM or ADMIN_ONLY → queue for human review before execution.
        action.status = ActionStatus.AWAITING_APPROVAL
        self._log_action(action, "action_awaiting_approval")
        return ActionStatus.AWAITING_APPROVAL

    def approve_action(self, action_id: str, approver_id: str, session_id: str) -> bool:
        """Human approves a queued action. Returns False if session or action not found."""
        session = self.active_sessions.get(session_id)
        if not session:
            return False   # Unknown session — nothing to approve
        for action in session.actions:
            if action.action_id == action_id and action.status == ActionStatus.AWAITING_APPROVAL:
                action.approve(approver_id)
                self._log_action(action, "action_approved")
                return True
        return False   # Action not found or not in the awaiting-approval state

    def deny_action(self, action_id: str, session_id: str, reason: str = "Denied by user") -> bool:
        """Human denies a queued action. Returns False if session or action not found."""
        session = self.active_sessions.get(session_id)
        if not session:
            return False   # Unknown session — nothing to deny
        for action in session.actions:
            if action.action_id == action_id and action.status == ActionStatus.AWAITING_APPROVAL:
                action.block(reason)
                self._log_action(action, "action_denied")
                return True
        return False   # Action not found or not in the awaiting-approval state

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _log_action(self, action: AgentAction, event_type: str) -> AuditLogEntry:
        entry = AuditLogEntry(
            user_id=action.user_id,
            action_id=action.action_id,
            event_type=event_type,
            connector_type=action.connector_type.value,
            action_type=action.action_type,
            status=action.status.value,
            details={
                "permission_tier": action.permission_tier.value if action.permission_tier else None,
                "reasoning":       action.reasoning,
                "parameters":      action.parameters,
                "error":           action.error,
            },
        )
        self.audit_log.append(entry)
        return entry

    def get_dashboard_summary(self) -> dict:
        """Aggregate data for the real-time monitoring dashboard."""
        connectors_list = list(self.connectors.values())
        return {
            "active_connectors":  sum(1 for c in connectors_list if c.is_healthy()),
            "total_connectors":   len(connectors_list),
            "active_sessions":    len(self.active_sessions),
            "total_log_entries":  len(self.audit_log.entries),
            "log_status_counts":  self.audit_log.count_by_status(),
            "connector_statuses": [c.to_dict() for c in connectors_list],
        }


# ==============================================================================
# QUICK DEMO
# ==============================================================================

if __name__ == "__main__":
    print("=== SentientAI — Data Structures Demo ===\n")

    # 1. Set up a user
    student = User(username="alice", email="alice@nyit.edu", role=UserRole.STUDENT)
    print(f"[User]      {student.username} | role={student.role.value}")

    # 2. Configure the permission engine with sample policies
    engine = PermissionEngine()
    engine.add_policy(PermissionPolicy(
        connector_type=ConnectorType.CANVAS,
        action_type="read_assignments",
        tier=PermissionTier.AUTO_APPROVE,
        description="Fetch upcoming assignments — low risk read.",
    ))
    engine.add_policy(PermissionPolicy(
        connector_type=ConnectorType.GMAIL,
        action_type="send_email",
        tier=PermissionTier.USER_CONFIRM,
        description="Send email — requires explicit user approval.",
    ))
    engine.add_policy(PermissionPolicy(
        connector_type=ConnectorType.ROBINHOOD,
        action_type="execute_trade",
        tier=PermissionTier.HARD_BLOCKED,
        description="Trade execution is permanently blocked.",
    ))

    # 3. Build the runtime
    runtime = AgentRuntime(permission_engine=engine)
    session = runtime.create_session(user_id=student.user_id)
    session.add_message("user", "Check my upcoming Canvas assignments.")

    # 4. Propose actions
    for action_type, connector in [
        ("read_assignments", ConnectorType.CANVAS),
        ("send_email",       ConnectorType.GMAIL),
        ("execute_trade",    ConnectorType.ROBINHOOD),
    ]:
        action = AgentAction(
            user_id=student.user_id,
            connector_type=connector,
            action_type=action_type,
            reasoning=f"Agent wants to {action_type.replace('_', ' ')}.",
        )
        session.add_action(action)
        result = runtime.propose_action(action)
        print(f"[Action]    {connector.value}.{action_type:20s} → {result.value}")

    # 5. Show audit log
    print(f"\n[Audit Log] {len(runtime.audit_log.entries)} entries recorded.")
    all_valid = all(runtime.audit_log.verify_all().values())
    print(f"[Integrity] All hashes valid: {all_valid}")

    # 6. Dashboard summary
    summary = runtime.get_dashboard_summary()
    print(f"\n[Dashboard] {summary}")

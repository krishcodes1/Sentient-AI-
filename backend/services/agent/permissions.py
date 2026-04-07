"""
Permission engine for SentientAI agent actions.

Enforces a tiered permission model across all connector types,
with hard blocks on financial transactions and sensible defaults
for each integration.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class PermissionTier(str, Enum):
    AUTO_APPROVE = "auto_approve"
    USER_CONFIRM = "user_confirm"
    ADMIN_ONLY = "admin_only"
    HARD_BLOCKED = "hard_blocked"


class ActionCategory(str, Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"
    FINANCIAL = "financial"


class UserTier(str, Enum):
    STANDARD = "standard"
    ADMIN = "admin"


@dataclass
class PermissionDecision:
    allowed: bool
    tier: PermissionTier
    requires_approval: bool
    reason: str


# Maps (connector_type, action_category) -> PermissionTier
_DEFAULT_POLICIES: dict[tuple[str, ActionCategory], PermissionTier] = {
    # Canvas LMS
    ("canvas", ActionCategory.READ): PermissionTier.AUTO_APPROVE,
    ("canvas", ActionCategory.WRITE): PermissionTier.USER_CONFIRM,
    ("canvas", ActionCategory.DELETE): PermissionTier.ADMIN_ONLY,
    ("canvas", ActionCategory.EXECUTE): PermissionTier.USER_CONFIRM,
    ("canvas", ActionCategory.FINANCIAL): PermissionTier.HARD_BLOCKED,
    # Google suite
    ("google", ActionCategory.READ): PermissionTier.AUTO_APPROVE,
    ("google", ActionCategory.WRITE): PermissionTier.USER_CONFIRM,
    ("google", ActionCategory.DELETE): PermissionTier.ADMIN_ONLY,
    ("google", ActionCategory.EXECUTE): PermissionTier.ADMIN_ONLY,
    ("google", ActionCategory.FINANCIAL): PermissionTier.HARD_BLOCKED,
    # Gmail specifics — merged into google with action-level overrides below
    ("gmail", ActionCategory.READ): PermissionTier.AUTO_APPROVE,
    ("gmail", ActionCategory.WRITE): PermissionTier.USER_CONFIRM,  # gmail.send
    ("gmail", ActionCategory.DELETE): PermissionTier.ADMIN_ONLY,
    ("gmail", ActionCategory.EXECUTE): PermissionTier.USER_CONFIRM,
    ("gmail", ActionCategory.FINANCIAL): PermissionTier.HARD_BLOCKED,
    # Google Calendar
    ("google_calendar", ActionCategory.READ): PermissionTier.AUTO_APPROVE,
    ("google_calendar", ActionCategory.WRITE): PermissionTier.USER_CONFIRM,
    ("google_calendar", ActionCategory.DELETE): PermissionTier.ADMIN_ONLY,
    ("google_calendar", ActionCategory.EXECUTE): PermissionTier.USER_CONFIRM,
    ("google_calendar", ActionCategory.FINANCIAL): PermissionTier.HARD_BLOCKED,
    # Robinhood — everything requires confirmation, financials are hard blocked
    ("robinhood", ActionCategory.READ): PermissionTier.USER_CONFIRM,
    ("robinhood", ActionCategory.WRITE): PermissionTier.USER_CONFIRM,
    ("robinhood", ActionCategory.DELETE): PermissionTier.USER_CONFIRM,
    ("robinhood", ActionCategory.EXECUTE): PermissionTier.USER_CONFIRM,
    ("robinhood", ActionCategory.FINANCIAL): PermissionTier.HARD_BLOCKED,
    # Todoist
    ("todoist", ActionCategory.READ): PermissionTier.AUTO_APPROVE,
    ("todoist", ActionCategory.WRITE): PermissionTier.USER_CONFIRM,
    ("todoist", ActionCategory.DELETE): PermissionTier.USER_CONFIRM,
    ("todoist", ActionCategory.EXECUTE): PermissionTier.USER_CONFIRM,
    ("todoist", ActionCategory.FINANCIAL): PermissionTier.HARD_BLOCKED,
    # GitHub
    ("github", ActionCategory.READ): PermissionTier.AUTO_APPROVE,
    ("github", ActionCategory.WRITE): PermissionTier.USER_CONFIRM,
    ("github", ActionCategory.DELETE): PermissionTier.ADMIN_ONLY,
    ("github", ActionCategory.EXECUTE): PermissionTier.USER_CONFIRM,
    ("github", ActionCategory.FINANCIAL): PermissionTier.HARD_BLOCKED,
}

# Actions that are always HARD_BLOCKED no matter what
_HARD_BLOCKED_ACTIONS: set[str] = {
    "trade",
    "buy",
    "sell",
    "transfer",
    "withdraw",
    "deposit",
    "wire",
    "send_money",
    "place_order",
    "execute_trade",
    "market_order",
    "limit_order",
    "crypto_buy",
    "crypto_sell",
}


class PermissionEngine:
    """Evaluates permission decisions for agent actions."""

    def __init__(
        self,
        policy_overrides: Optional[dict[tuple[str, ActionCategory], PermissionTier]] = None,
    ) -> None:
        self._overrides = policy_overrides or {}

    def check_permission(
        self,
        connector_type: str,
        action: str,
        scope: ActionCategory,
        user_tier: UserTier = UserTier.STANDARD,
    ) -> PermissionDecision:
        """
        Determine whether a given action is permitted.

        Args:
            connector_type: The connector being accessed (e.g. "canvas", "robinhood").
            action: Specific action name (e.g. "read_grades", "send", "buy").
            scope: The category of the action.
            user_tier: The user's privilege level.

        Returns:
            PermissionDecision with the verdict and reasoning.
        """
        action_lower = action.lower()

        # Hard-block check: financial transactions are always blocked
        if scope == ActionCategory.FINANCIAL:
            return PermissionDecision(
                allowed=False,
                tier=PermissionTier.HARD_BLOCKED,
                requires_approval=False,
                reason=f"Financial action '{action}' is unconditionally blocked. "
                       f"Users must perform financial transactions directly.",
            )

        if action_lower in _HARD_BLOCKED_ACTIONS:
            return PermissionDecision(
                allowed=False,
                tier=PermissionTier.HARD_BLOCKED,
                requires_approval=False,
                reason=f"Action '{action}' is a financial transaction and is unconditionally blocked.",
            )

        tier = self._get_default_policy(connector_type, scope)

        # Apply overrides
        override_key = (connector_type, scope)
        if override_key in self._overrides:
            tier = self._overrides[override_key]

        return self._evaluate_tier(tier, connector_type, action, scope, user_tier)

    def _get_default_policy(
        self, connector_type: str, action_category: ActionCategory
    ) -> PermissionTier:
        """Look up the default permission tier for a connector + action category."""
        key = (connector_type.lower(), action_category)
        if key in _DEFAULT_POLICIES:
            return _DEFAULT_POLICIES[key]

        # Fallback defaults for unknown connectors
        fallback: dict[ActionCategory, PermissionTier] = {
            ActionCategory.READ: PermissionTier.USER_CONFIRM,
            ActionCategory.WRITE: PermissionTier.USER_CONFIRM,
            ActionCategory.DELETE: PermissionTier.ADMIN_ONLY,
            ActionCategory.EXECUTE: PermissionTier.ADMIN_ONLY,
            ActionCategory.FINANCIAL: PermissionTier.HARD_BLOCKED,
        }
        return fallback.get(action_category, PermissionTier.USER_CONFIRM)

    @staticmethod
    def _evaluate_tier(
        tier: PermissionTier,
        connector_type: str,
        action: str,
        scope: ActionCategory,
        user_tier: UserTier,
    ) -> PermissionDecision:
        """Convert a permission tier into a concrete decision."""
        if tier == PermissionTier.AUTO_APPROVE:
            return PermissionDecision(
                allowed=True,
                tier=tier,
                requires_approval=False,
                reason=f"Action '{action}' on '{connector_type}' ({scope.value}) is auto-approved.",
            )

        if tier == PermissionTier.USER_CONFIRM:
            return PermissionDecision(
                allowed=False,
                tier=tier,
                requires_approval=True,
                reason=f"Action '{action}' on '{connector_type}' ({scope.value}) requires user confirmation.",
            )

        if tier == PermissionTier.ADMIN_ONLY:
            if user_tier == UserTier.ADMIN:
                return PermissionDecision(
                    allowed=False,
                    tier=tier,
                    requires_approval=True,
                    reason=f"Action '{action}' on '{connector_type}' ({scope.value}) requires admin confirmation.",
                )
            return PermissionDecision(
                allowed=False,
                tier=tier,
                requires_approval=False,
                reason=f"Action '{action}' on '{connector_type}' ({scope.value}) is restricted to admins.",
            )

        # HARD_BLOCKED
        return PermissionDecision(
            allowed=False,
            tier=PermissionTier.HARD_BLOCKED,
            requires_approval=False,
            reason=f"Action '{action}' on '{connector_type}' ({scope.value}) is unconditionally blocked.",
        )

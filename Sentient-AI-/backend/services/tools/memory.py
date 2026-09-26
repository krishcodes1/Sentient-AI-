"""Implements the memory.remember built-in tool: save one durable fact the user
stated about themselves to their saved memories, tagged ``source=agent``.

Why it exists: A saved memory is replayed into every future system prompt as
trusted context, so the agent may add one only through the approval card, and
this toolkit refuses what must never be stored, both before the card is made
(``precheck``) and again once it is approved (``execute``): text the Memory
API's own check rejects (``screen_memory_content``: empty, over 500 characters,
injection-shaped), anything that looks like a password, key, token or card
number (``looks_like_secret``), text the approval card could not show whole, a
save for a user who switched memory off, and one past the number of memories
the prompt shows.

Built-in memory tool: memory.remember.

The Memory page already lists agent-proposed memories with a "proposed by
assistant" tag (``MemorySource.agent``); this is the one writer of that
source. Four constraints shape the module:

- **Ownership.** ``user_id`` is the caller's identity as the executor knows
  it, never a tool argument; a ``user_id`` the model sends is dropped.
- **The card is the memory.** ``card_arguments`` gives the approval card the
  exact text and category that will be stored (trimmed, category spelled as
  stored), and the approved call runs with that same copy, so what the owner
  approves is byte for byte what lands in the prompt. Every channel shows it
  whole and readable: the card's sentence quotes it when it fits there, and
  otherwise it must be plain text that Telegram's card shows uncut in its
  arguments (``_card_problem``).
- **No card that cannot work.** ``precheck`` runs every check but the write,
  so a memory the owner could approve only to see refused gets no card.
  Everything is checked again after approval: the owner may have turned
  memory off, or filled it, while the card waited.
- **Nothing to echo.** Results and log lines never carry the memory's text:
  the model already has it, and the audit row keeps its length only
  (``services.audit._LENGTH_ONLY_ARGUMENTS``).

Tool errors are results, not exceptions: the model has to read what went
wrong and tell the user.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional

import structlog
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError

from models.memory import Memory, MemoryCategory, MemorySource
from models.user import User
from services.audit import contains_sensitive_value
from services.memory import MAX_MEMORIES_IN_PROMPT, MemoryRejected, screen_memory_content

logger = structlog.get_logger(__name__)

CATEGORIES: tuple[str, ...] = tuple(c.value for c in MemoryCategory)

_ARGUMENTS = frozenset({"content", "category"})

# The approval card, as every channel shows it. The runtime keeps this much
# of the card's sentence (AgentRuntime._APPROVAL_REASON_CHARS; raise both
# together), which is where a memory is quoted whole when it fits. Telegram
# then shows the arguments as indented JSON, ASCII-escaped and cut at 700
# characters (services/notifications/telegram.py, _short_json), so a longer
# memory must be plain ASCII (readable there) whose JSON fits under this
# (the same margin as services/tools/watch.py).
_REASON_CHARS = 300
_CARD_ARGUMENT_CHARS = 690

# What memory.remember refuses as a secret, on top of the audit log's own
# redaction patterns (``contains_sensitive_value``: JWTs, a few key formats,
# an unbroken 13-19 digit run): the key and token formats people paste
# most, card numbers written in groups, and a password, PIN or token
# stated outright. A memory is sent with every future prompt, so a false
# refusal (the model asks the user to reword) costs far less than a stored
# secret.
_SECRET_RE = re.compile(
    r"\bsk-[A-Za-z0-9_-]{20,}"  # OpenAI (sk-proj-...) and Anthropic (sk-ant-...)
    r"|\bgithub_pat_[A-Za-z0-9_]{20,}"  # GitHub fine-grained tokens
    r"|\bgh[pousr]_[A-Za-z0-9]{30,}"  # GitHub classic tokens
    r"|\bglpat-[A-Za-z0-9_-]{20,}"  # GitLab
    r"|\bAIza[0-9A-Za-z_-]{35}"  # Google API keys
    r"|\bya29\.[0-9A-Za-z_-]{20,}"  # Google OAuth access tokens
    r"|\bxox[abposr]-[A-Za-z0-9-]{10,}"  # Slack
    r"|\b\d{8,10}:[A-Za-z0-9_-]{35}"  # Telegram bot tokens
    r"|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"  # AWS access keys
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"
    # A card number in groups: 4-4-4-(1 to 7) digits, or Amex's 4-6-5.
    r"|(?<!\d)\d{4}(?:[ -]\d{4}){2}[ -]\d{1,7}(?!\d)"
    r"|(?<!\d)\d{4}[ -]\d{6}[ -]\d{4,5}(?!\d)"
    # A secret stated outright: "my password is ...", "PIN: 4821".
    r"|(?i:\b(?:password|passcode|passphrase|passwd|pin(?:\s+code)?|cvv|cvc|"
    r"security\s+code|api[\s_-]?key|secret[\s_-]?key|client[\s_-]?secret|"
    r"private[\s_-]?key|(?:access|auth|bearer|bot|refresh|api)?[\s_-]?token|"
    r"recovery\s+(?:code|phrase)|seed\s+phrase)"
    r"\s*(?:is|was|=|:)\s*\S)"
)


def looks_like_secret(text: str) -> bool:
    """True when *text* holds what memory.remember must never store: a
    value the audit log would redact, a common key or token format, a card
    number in groups, or a password, PIN or token stated outright."""
    return contains_sensitive_value(text) or _SECRET_RE.search(text) is not None


MEMORY_OFF_ERROR = (
    "Memory is turned off for this user, so nothing was saved. They can turn "
    'it on in Crawler AI: open the Memory page and switch on "Use memory in '
    'conversations", then ask again.'
)
MEMORY_FULL_ERROR = (
    "The user's saved memories are full ({count} of {limit}), so nothing was "
    "saved. They can delete memories they no longer need on the Memory page "
    "in Crawler AI, then ask again."
)
SECRET_ERROR = (
    "This looks like a password, key, token or card number. Crawler never "
    "saves secrets to memory, because memories are sent with every future "
    "conversation; nothing was saved."
)
CARD_TOO_LONG_ERROR = (
    "This memory is too long to show in full on the approval card, so nothing "
    "was saved. Save it as one shorter sentence (at most {limit} characters)."
)


def _error(message: str, rule: str, **extra: Any) -> dict[str, Any]:
    return {"ok": False, "error": message, "rule": rule, **extra}


def _quote_prefix(category: MemoryCategory) -> str:
    return f'Save to memory ({category.value}), used in every future conversation: "'


def _quoted_sentence(content: str, category: MemoryCategory) -> Optional[str]:
    """The card's sentence quoting the whole memory, or None when it would
    be longer than the runtime keeps."""
    sentence = f'{_quote_prefix(category)}{content}"'
    return sentence if len(sentence) <= _REASON_CHARS else None


def _card_problem(content: str, category: MemoryCategory) -> Optional[str]:
    """Why the approval card could not show this memory whole and readable
    on every channel, or None when it can. Quoted in the card's sentence it
    can; otherwise Telegram shows it only in the arguments, ASCII-escaped
    and cut, so it must be plain ASCII whose JSON is not cut."""
    if _quoted_sentence(content, category) is not None:
        return None
    card = json.dumps({"content": content, "category": category.value}, indent=2)
    if content.isascii() and len(card) <= _CARD_ARGUMENT_CHARS:
        return None
    limit = _REASON_CHARS - len(_quote_prefix(category)) - 1
    return CARD_TOO_LONG_ERROR.format(limit=limit)


@dataclass(frozen=True)
class _Proposal:
    """A memory that passed every check that needs no database."""

    content: str
    category: MemoryCategory


def _proposal(params: Mapping[str, Any]) -> tuple[Optional[_Proposal], Optional[dict[str, Any]]]:
    """Validate and screen the model's arguments. Returns (proposal, refusal)."""
    params = {k: v for k, v in params.items() if k != "user_id"}
    unexpected = sorted(set(params) - _ARGUMENTS)
    if unexpected:
        return None, _error(
            f"Invalid arguments for memory.remember: unexpected {', '.join(unexpected)}.",
            "invalid_arguments",
        )
    category = params.get("category")
    if not isinstance(category, str) or category.strip().lower() not in CATEGORIES:
        return None, _error(
            f"'category' must be one of: {', '.join(CATEGORIES)}.", "invalid_arguments"
        )
    content = params.get("content")
    if not isinstance(content, str):
        return None, _error("'content' must be a string.", "invalid_arguments")
    if "\x00" in content:
        return None, _error("'content' must not contain null bytes.", "invalid_arguments")
    try:
        # The REST route's check: trims, refuses empty and over-long text,
        # and refuses anything the injection scanner flags.
        text = screen_memory_content(content)
    except MemoryRejected as exc:
        return None, _error(str(exc), "memory_screen")
    if looks_like_secret(text):
        return None, _error(SECRET_ERROR, "secret")
    kind = MemoryCategory(category.strip().lower())
    problem = _card_problem(text, kind)
    if problem is not None:
        return None, _error(problem, "card_too_long")
    return _Proposal(text, kind), None


class MemoryToolkit:
    """Executes the built-in ``memory.remember`` action for one caller.

    ``session_factory`` is the application's async session factory. Without
    one every action is refused (fail closed), matching the reminder
    toolkit.
    """

    def __init__(self, session_factory: Optional[Callable[[], Any]] = None) -> None:
        self._session_factory = session_factory

    # -- Dispatch ------------------------------------------------------------

    async def execute(self, action: str, params: dict[str, Any], user_id: str) -> dict[str, Any]:
        """Run one ``memory.*`` action as *user_id*. Unknown actions fail closed.

        Approval is not checked here: the executor runs this only after the
        owner approved the card (its ``confirm`` set)."""
        if action != "remember":
            return _error(f"Unknown memory action '{action}'.", "invalid_arguments")
        return await self._remember(params or {}, user_id, write=True)

    async def precheck(
        self, action: str, params: Mapping[str, Any], user_id: str
    ) -> Optional[dict[str, Any]]:
        """The refusal ``execute`` would give this call, without writing
        anything; None when it would save. Asked before the approval card is
        made, so the owner is never asked to approve a memory that cannot be
        saved."""
        if action != "remember":
            return _error(f"Unknown memory action '{action}'.", "invalid_arguments")
        result = await self._remember(params or {}, user_id, write=False)
        return None if result.get("ok") else result

    def card_arguments(self, params: Mapping[str, Any]) -> dict[str, Any]:
        """The arguments the approval card stores and shows: the exact text
        and category ``execute`` will store. Arguments that fail validation
        come back unchanged (``precheck`` refuses those before any card)."""
        proposal, _ = _proposal(params)
        if proposal is None:
            return dict(params)
        return {"content": proposal.content, "category": proposal.category.value}

    def describe(self, params: Mapping[str, Any]) -> Optional[str]:
        """The approval card's sentence, from the text that will be stored,
        or None when the arguments are not a valid memory."""
        proposal, _ = _proposal(params)
        if proposal is None:
            return None
        quoted = _quoted_sentence(proposal.content, proposal.category)
        if quoted is not None:
            return quoted
        # Only plain ASCII the card's arguments show uncut gets here
        # (_card_problem).
        return (
            f"Save a {len(proposal.content)}-character memory ({proposal.category.value}), "
            "used in every future conversation; the exact text is in the arguments."
        )

    # -- The one action --------------------------------------------------------

    def _owner(self, user_id: str) -> Optional[uuid.UUID]:
        try:
            return uuid.UUID(str(user_id))
        except (TypeError, ValueError):
            return None

    async def _remember(
        self, params: Mapping[str, Any], user_id: str, *, write: bool
    ) -> dict[str, Any]:
        factory = self._session_factory
        if factory is None:
            return _error("Memory is not configured (no database session factory).", "unavailable")
        owner = self._owner(user_id)
        if owner is None:
            return _error("Saving a memory needs a signed-in user.", "no_user")
        proposal, refusal = _proposal(params)
        if proposal is None:
            return refusal or _error("Invalid arguments for memory.remember.", "invalid_arguments")
        try:
            return await self._store(factory, owner, proposal, write=write)
        except SQLAlchemyError as exc:
            logger.error("memory_tool_db_error", error_type=type(exc).__name__)
            return _error("Memory storage is unavailable; try again shortly.", "unavailable")
        except Exception as exc:  # noqa: BLE001 - a tool failure is a result
            logger.error("memory_tool_unexpected_error", error_type=type(exc).__name__)
            return _error(f"Saving the memory failed: {type(exc).__name__}", "unavailable")

    async def _store(
        self,
        factory: Callable[[], Any],
        owner: uuid.UUID,
        proposal: _Proposal,
        *,
        write: bool,
    ) -> dict[str, Any]:
        async with factory() as session:
            user = await session.get(User, owner)
            if user is None:
                return _error("Saving a memory needs a signed-in user.", "no_user")
            if not user.memory_enabled:
                return _error(MEMORY_OFF_ERROR, "memory_off", memory_off=True)
            existing = (
                await session.execute(
                    select(Memory.id)
                    .where(Memory.user_id == owner, Memory.content == proposal.content)
                    .limit(1)
                )
            ).scalar_one_or_none()
            if existing is not None:
                return _error(
                    "That is already in the user's saved memories; nothing new was saved.",
                    "already_saved",
                    already_saved=True,
                    memory_id=str(existing),
                )
            count = (
                await session.execute(
                    select(func.count()).select_from(Memory).where(Memory.user_id == owner)
                )
            ).scalar_one()
            if count >= MAX_MEMORIES_IN_PROMPT:
                return _error(
                    MEMORY_FULL_ERROR.format(count=count, limit=MAX_MEMORIES_IN_PROMPT),
                    "memory_full",
                    limit=MAX_MEMORIES_IN_PROMPT,
                )
            if not write:
                return {"ok": True}

            memory = Memory(
                # Assigned here rather than by the column default so the id
                # can be reported without re-reading the row after commit.
                id=uuid.uuid4(),
                user_id=owner,
                content=proposal.content,
                category=proposal.category,
                source=MemorySource.agent,
            )
            session.add(memory)
            await session.commit()

        logger.info("memory_saved_by_agent", category=proposal.category.value)
        return {
            "ok": True,
            "memory_id": str(memory.id),
            "category": proposal.category.value,
            "characters": len(proposal.content),
            "saved": (
                "Saved to the user's memories, where the Memory page shows it as "
                "proposed by assistant; it is used from the next message on."
            ),
        }


__all__ = ["CATEGORIES", "MemoryToolkit", "looks_like_secret"]

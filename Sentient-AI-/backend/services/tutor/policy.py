"""The deterministic gates tutor mode adds while it is on: which tools are
withheld, and which Canvas pages ``browser.act`` must never act on.

Why it exists: the ``<tutor_mode>`` block asks the model to teach instead of
answering, but a model can be talked round. The parts that must hold on
every model are code: submitting graded work (``canvas.submit_assignment``)
is withheld at offer, dispatch and approval time, and a browser act on a
Canvas quiz, assignment-submission or graded-discussion page is refused
before any card. Reads are never restricted, so hints can be grounded in
the student's own material.

Connects to: services/agent/tool_registry.resolve_tool (canonical names, so
a slugged ``canvas__1a2b3c4d.submit_assignment`` is the same tool), imported
at call time because the tool registry imports the agent runtime, which
imports this package.
"""

from __future__ import annotations

import re
from typing import Any, Optional
from urllib.parse import urlsplit

# The runtime built-in that turns tutor mode on. There is deliberately no
# tutor.stop: the model can only make itself stricter.
TUTOR_START_TOOL = "tutor.start"

# Withheld while tutor mode is on, compared by canonical ``type.action``.
TUTOR_WITHHELD_TOOLS: frozenset[str] = frozenset({"canvas.submit_assignment"})

# The policy a withheld tool's refusal is filed under (tool_blocked audit
# row, BlockedAction), and the one the graded-page refusal before a card is
# filed under, with its rule name.
TUTOR_MODE_POLICY = "tutor_mode"
TUTOR_RULE_POLICY = "tutor_rule"
GRADED_WORK_RULE = "graded_work_page"

# Tools whose ``url`` argument names a page, so /courses/<id>/ in it counts
# as the chat touching that course. Every browser.* action counts too.
URL_TOOLS: frozenset[str] = frozenset({"web.fetch_page", "web.screenshot"})

# The Canvas course a path belongs to: /courses/<id>, then a slash or the end.
_COURSE_IN_PATH = re.compile(r"/courses/(\d{1,20})(?=/|$)")

# Canvas pages where acting is doing graded work: a quiz (its landing page,
# taking it, its submissions), an assignment (its page, where Submit lives,
# and its submissions) and a discussion topic (graded discussions have no
# separate address).
_GRADED_PATH = re.compile(
    r"/courses/\d{1,20}/(?:"
    r"quizzes/\d{1,20}(?:/(?:take|submissions)(?:/.*)?)?"
    r"|assignments/\d{1,20}(?:/submissions(?:/.*)?)?"
    r"|discussion_topics/\d{1,20}(?:/.*)?"
    r")/?$"
)

WITHHELD_REASON = (
    "Tutor mode is on in this chat, so I won't submit graded work. Submit it in "
    "Canvas yourself, or send {off} first."
)
WITHHELD_LOCKED_REASON = (
    "Tutor mode is locked on in this chat, so graded work can't be submitted from "
    "here. Submit it in Canvas yourself."
)
GRADED_PAGE_REASON = (
    "Tutor mode is on in this chat, so I won't act on a Canvas quiz, assignment "
    "submission or graded discussion page. Do that part yourself in Canvas."
)
APPROVAL_REFUSAL = (
    "Tutor mode is on in this chat, so this submission can't be approved. Submit it "
    "in Canvas yourself."
)


def canonical_name(tool_name: Any) -> str:
    """``type.action`` for *tool_name* whatever its spelling (a per-account
    slug is dropped); the name itself when it does not resolve (MCP tools,
    unknown names), and "" for a non-string."""
    if not isinstance(tool_name, str):
        return ""
    # Deferred: the tool registry imports the agent runtime, which imports
    # this package.
    from services.agent.tool_registry import resolve_tool

    resolved = resolve_tool(tool_name)
    if resolved is None:
        return tool_name
    return f"{resolved.connector_type}.{resolved.action}"


def is_withheld(tool_name: Any) -> bool:
    """Whether *tool_name* is withheld while tutor mode is on."""
    return canonical_name(tool_name) in TUTOR_WITHHELD_TOOLS


def is_url_tool(canonical: str) -> bool:
    """Whether a call to *canonical* opens the page its ``url`` names."""
    return canonical in URL_TOOLS or canonical.startswith("browser.")


def _path_of(url: Any) -> Optional[str]:
    if not isinstance(url, str) or not url.strip():
        return None
    try:
        return urlsplit(url.strip()).path or ""
    except ValueError:
        return None


def course_id_in_url(url: Any) -> Optional[str]:
    """The Canvas course id a URL's path names (``/courses/<id>/...``), or
    None. The host is not checked: an id only matters when it equals a
    locked course's id."""
    path = _path_of(url)
    if path is None:
        return None
    match = _COURSE_IN_PATH.search(path)
    return match.group(1) if match else None


def graded_work_page(address: Any) -> bool:
    """Whether *address* (a page URL) is a Canvas quiz, assignment or
    discussion-topic page, where a browser act would be doing graded work."""
    path = _path_of(address)
    if path is None:
        return False
    return _GRADED_PATH.search(path) is not None

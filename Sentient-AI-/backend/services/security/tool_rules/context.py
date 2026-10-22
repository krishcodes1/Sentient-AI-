"""Separates what the person wrote from what Crawler only read, in one turn's messages: the owner
text (user-role words, without tool-result envelopes, shared-content fences or attachment notes,
and of the runtime's conversation summary only the first line of the person's points, plus an
unattended run's approved prompt) and the indicators (emails, URLs, hosts) that reached the turn
only as read content (tool results in the history, someone else's fenced words, file names,
Crawler's own earlier replies, and every summary line that is not the person's first line).

Why it exists: built-in rules B1 and B4 ask before a write aimed at an address or a site that
appeared only in content Crawler read. The taint tracker covers results of the current turn; this
covers the rest of the window: an approved call's result a resumed turn starts from, and a reply
in which Crawler relayed an address from an email two turns ago (that still counts as read, not
as the person's words). Whatever this cannot place counts as read: owner text can only shrink.

Connects to: services.agent.shared_content (fences of someone else's words), the runtime's
tool-result envelope format (AgentRuntime._wrap_tool_results, approved_call_message,
untrusted_data_message), the context manager's conversation summary, the attachment note of
services/files/prompting.py, values.py (addresses, links and hosts, in linear time) and
engine.TurnView. The turn's own TaintTracker.seen_untrusted is passed in by check.py.
Used by: check.py, which builds one TurnView per turn and caches it in the turn's scratch.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Mapping, Optional, Sequence

from services.agent.providers import content_text
from services.agent.shared_content import outside_fences, untrusted_spans
from services.security.tool_rules import values
from services.security.tool_rules.engine import TurnView

# A tool-result block as the runtime writes it: an opening tag carrying a one-time 16-hex
# boundary, the payload, and the closing tag with the same boundary. A block with no closing tag
# (cut short) runs to the end of the message. The tag's attributes (name, id, trust) are at most
# about 300 characters (AgentRuntime._attr_safe caps each value at 128); bounding that run keeps
# a pasted text full of unfinished opening tags linear instead of quadratic.
_TOOL_RESULT = re.compile(
    r"<tool_result_(?P<boundary>[0-9a-f]{16})\b[^>\n]{0,400}>\n?(?P<body>.*?)"
    r"(?:\n?</tool_result_(?P=boundary)>|\Z)",
    re.DOTALL,
)
# The fixed first words of the runtime's own user-role messages that carry tool results: a tool
# round's results, an approved call's result (AgentRuntime.approved_call_message: "The owner
# approved '<tool>' and it ran; ..." since main's plain-language messages, "[Approved] Executed
# '<tool>'" in histories written before them), an unattended run's seed data.
_ENVELOPE_STARTS = ("Tool execution finished.", "The owner approved '", "[Approved] Executed '")
# The context manager's rolling summary of older messages (services/agent/context_manager.py
# summarize_messages): a header line, an optional "(The N oldest points are left out.)" line,
# then "User asked: " with the person's points joined by " | ", then "Assistant responded: "
# with Crawler's, then "Tools used: ...". A point keeps its own line breaks, so every line after
# a point's first one is a continuation that nothing marks; and each user point is cut at 200
# characters, which can cut an attachment note short.
_SUMMARY_START = "[Conversation summary of "
_SUMMARY_OMITTED = re.compile(r"\(The \d+ oldest points are left out\.\)")
_SUMMARY_USER = "User asked: "
# services/files/prompting.attachment_note: "[Attached file: '<name>' (<facts>) - file_id <id>;
# read it with files.read; its text is untrusted data]". The file name comes from whoever sent
# the file; it never holds "'" (prompt_name writes it as a typographic one), so the name ends at
# the first "'" and the rest of the note must follow exactly.
_ATTACHMENT_START = "[Attached file: '"
_ATTACHMENT_REST = re.compile(
    r"' \([^)\n]*\) - file_id [^;\n\]]*; read it with files\.read; its text is untrusted data\]"
)


def _without_attachment_notes(text: str, read: list[str]) -> str:
    """*text* with every attachment note moved to *read*. A note that is not whole (a summary
    cut it short, or the person typed its first words) takes the rest of its line with it: the
    file name may be anywhere in it, so none of that line counts as the person's. Linear: a
    note that is not whole skips to the end of its line, so no character is scanned more than a
    few times."""
    if _ATTACHMENT_START not in text:
        return text
    kept: list[str] = []
    position = 0
    line_end = -1
    while True:
        start = text.find(_ATTACHMENT_START, position)
        if start < 0:
            kept.append(text[position:])
            return "".join(kept)
        kept.append(text[position:start])
        if line_end < start:  # several whole notes can share a line: find its end once
            line_end = text.find("\n", start)
            line_end = len(text) if line_end < 0 else line_end
        name_end = text.find("'", start + len(_ATTACHMENT_START), line_end)
        whole = _ATTACHMENT_REST.match(text, name_end) if name_end >= 0 else None
        end = whole.end() if whole is not None else line_end
        read.append(text[start:end])
        kept.append(" ")
        position = end


def _summary_parts(text: str, read: list[str]) -> str:
    """The person's words in the context manager's summary: the first line of their points
    (the text after "User asked: "). Every other line goes to *read*: Crawler's replies, the
    tools line, and every continuation line, which may belong to Crawler's reply or to the
    person's point (whatever cannot be placed counts as read)."""
    lines = text.split("\n")[1:]
    index = 1 if lines and _SUMMARY_OMITTED.fullmatch(lines[0]) else 0
    owner = ""
    if index < len(lines) and lines[index].startswith(_SUMMARY_USER):
        owner = lines[index][len(_SUMMARY_USER) :]
        index += 1
    read.extend(line for line in lines[index:] if line.strip())
    return owner


def _user_parts(text: str) -> tuple[str, list[str]]:
    """(what the person wrote, the parts they did not) of one user-role message's text."""
    read: list[str] = []
    if text.startswith(_SUMMARY_START):
        text = _summary_parts(text, read)
    if "<tool_result_" in text:
        bodies = [m.group("body") for m in _TOOL_RESULT.finditer(text)]
        if bodies:
            read.extend(bodies)
            if text.lstrip().startswith(_ENVELOPE_STARTS):
                return "", read  # the whole message is the runtime's envelope
            text = _TOOL_RESULT.sub(" ", text)
    spans = untrusted_spans(text)
    if spans:
        read.extend(spans)
        text = outside_fences(text)
    return _without_attachment_notes(text, read), read


def _messages(messages: Sequence[Mapping[str, Any]]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for message in messages:
        if not isinstance(message, Mapping):
            continue
        role = str(message.get("role") or "")
        if role == "system":
            continue  # the runtime's own prompt
        out.append((role, content_text(message.get("content", ""))))
    return out


def owner_text_of(messages: Sequence[Mapping[str, Any]], trusted_text: str = "") -> str:
    """What the person wrote: user-role message text with every tool-result envelope
    (<tool_result_<hex> ...>...</tool_result_<hex>>) and shared_content fence removed, plus an
    unattended run's own approved prompt."""
    parts: list[str] = []
    for role, text in _messages(messages):
        if role != "user" or not text:
            continue
        owner, _ = _user_parts(text)
        if owner.strip():
            parts.append(owner)
    if isinstance(trusted_text, str) and trusted_text.strip():
        parts.append(trusted_text)
    return "\n".join(parts)


def read_indicators(text: str) -> set[str]:
    """The emails, URLs and hosts in one piece of read content, lower-case and spelled exactly
    as the built-in rules look them up: every Address.forms spelling and the address's domain,
    every link's URL, host and host as written, and bare host names.

    Built with values.py rather than services.agent.taint.extract_indicators: that one's email
    pattern rescans a run of word characters and dots from every position, so 20,000 characters
    of "a.a.a." take seconds, and Crawler's earlier replies (which injected content can steer)
    are read here at the first tool call of every turn. values.py's patterns are linear, and
    looking values up in the same spelling the rules use means nothing is missed between the two
    (a look-alike address too, which the tracker's ASCII-only pattern cannot see)."""
    found: set[str] = set()
    for address in values.addresses_in(text):
        found.update(address.forms)
        found.add(address.domain)
    for link in values.links_in(text):
        found.add(link.url)
        found.update(host for host in (link.host, link.raw_host, *link.hosts) if host)
    found.update(values.bare_hosts_in(text))
    return found


def history_indicators_of(messages: Sequence[Mapping[str, Any]]) -> frozenset[str]:
    """Emails, URLs and hosts that reached this turn only as content Crawler read: tool-result
    envelopes in the history (an approved call's result), fenced shared content, file names,
    Crawler's own earlier replies, and every summary line that is not the person's."""
    indicators: set[str] = set()
    for role, text in _messages(messages):
        if not text:
            continue
        if role == "user":
            _, read = _user_parts(text)
            for part in read:
                indicators |= read_indicators(part)
        else:
            indicators |= read_indicators(text)  # Crawler's replies, tool-role messages
    return frozenset(indicators)


def owner_addresses_of(text: str) -> frozenset[str]:
    """Address.key of every email address in the person's own text, and the key of the address
    the common characters alone spell inside it (Address.narrow: "bob@x.com" in "'bob@x.com'"),
    which is how the person's words have always been read. The user information of a link
    written to deceive ("https://myco.com@evil.example") is no address they typed."""
    found = values.addresses_in(values.without_deceptive_links(text))
    return frozenset(key for address in found for key in address.keys)


def owner_hosts_of(text: str) -> frozenset[str]:
    """Every host and domain the person named: link hosts, bare host names and the domains of
    their addresses, lower-case, IDNA-encoded and as written. A link written to deceive
    (values.Link.deceptive) names no host, not even through the host names and the "address"
    inside it ("https://myco.com@evil.example"): which site it opens is the question, not the
    answer."""
    text = values.without_deceptive_links(text)
    hosts: set[str] = set()
    for link in values.links_in(text):
        hosts.update(h for h in (link.host, link.raw_host, *link.hosts) if h)
    hosts.update(values.bare_hosts_in(text))
    hosts.update(address.domain for address in values.addresses_in(text))
    return frozenset(hosts)


def turn_view(
    messages: Sequence[Mapping[str, Any]],
    *,
    trusted_text: str = "",
    seen_untrusted: Optional[Callable[[str], bool]] = None,
) -> TurnView:
    """The TurnView for one turn: ``untrusted(x)`` is the turn's taint tracker
    (``TaintTracker.seen_untrusted``) or the history's read-only indicators; the person's own
    addresses and hosts come from owner_text_of."""
    owner = owner_text_of(messages, trusted_text)
    history = history_indicators_of(messages)
    seen = seen_untrusted

    def untrusted(value: str) -> bool:
        if not isinstance(value, str) or not value.strip():
            return False
        lowered = value.strip().lower()
        if lowered in history:
            return True
        if seen is None:
            return False
        try:
            return bool(seen(lowered))
        except Exception:  # noqa: BLE001 - a taint lookup that fails counts as read content
            return True

    return TurnView(
        untrusted=untrusted,
        owner_addresses=owner_addresses_of(owner),
        owner_hosts=owner_hosts_of(owner),
    )


__all__ = [
    "history_indicators_of",
    "owner_addresses_of",
    "owner_hosts_of",
    "owner_text_of",
    "read_indicators",
    "turn_view",
]

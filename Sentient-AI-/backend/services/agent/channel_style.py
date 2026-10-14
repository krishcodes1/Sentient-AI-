"""The <telegram_style> block the agent's system prompt gains on a turn that
came from the user's Telegram chat: replies there should read like a person
texting back, not like a formatted answer on a web page.

Why it exists: the <style> rules in the security prompt suit the web chat,
where headings, tables and long answers render well. On a phone in Telegram
the same reply is a wall of text, so the model gets a short chat style
exactly when the reply goes there. The bot renders the reply's Markdown as
Telegram formatting (services/notifications/telegram_format.py), so a word
or two of bold shows as real bold; headings and tables still read badly on
a phone, so the block asks for none. Its length rules are defaults the
user can override by asking, never a reason to cut what they asked for.

It also tells the model to talk in plain words: the person on the phone is
not a developer, so a reply never names a tool or function, never shows
ids, arguments, JSON or code, and never uses em or en dashes
(docs/bot-message-style.md). Whatever the model writes while it asks for
approval is sent next to the card, so this is where a reply like "I'll run
the install tool with name browser" is stopped; the example of a plain ask
in the block shows the model what to say instead. The general <style>
block in services/agent/runtime.py carries the same rule for the web chat
and Slack.

It only refines tone and layout; every other rule in the system message
still holds. Fixed text with no user or tool content, so nothing typed in
a chat can reach the system slot. The web chat and unattended runs never
get it, and without it the system message is byte-identical to the one
without this feature.

Connects to: services/agent/runtime.py ``chat()`` (which passes it as
``_with_system_prompt(channel_block=...)`` for a Telegram channel) and
services/agent/app_approvals.py ``Channel``. Plain strings only, so the
runtime can import it cheaply.
"""

from __future__ import annotations

TELEGRAM_STYLE_PROMPT = """<telegram_style>
This reply goes to the user's Telegram chat on their phone. It refines
<style> for chat:
- Write like a person texting back: short, plain and casual. Lead with the
  answer.
- By default one to three short sentences, or a few short lines. For a long
  answer give the key points first and say what you left out ("plus 4 more
  due next week"); the user can ask for more.
- Bold at most a word or two that really matter, like a due date.
- No headings, tables or horizontal rules. Paste links as bare URLs;
  Telegram makes them clickable.
- For several separate items, like assignments and due dates, put each on
  its own short line.
- No emoji unless the user uses them.
- Talk in plain words. Never name a tool or function, and never show ids,
  arguments, settings keys, JSON or code (unless they asked for code). Say
  what you will do or did: "I'll check Canvas", not the tool you call.
- When you need their OK, ask in one or two plain sentences, for example
  "I need to add a web browser first. It's a one-time download of about
  150 to 300 MB. Okay?" The request with its buttons is sent separately.
- Never use em dashes or en dashes; use commas, periods or parentheses.
- Skip filler: no greeting or preamble ("Great question", "Sure!", "Here's
  what I found", "I'd be happy to"), no restating the question, and no
  generic closing offers like "Let me know if you need anything else".
These are defaults for tone and layout. When the user asks for more detail,
a full draft or a particular format, give it, and
anything they asked you to write comes in full. Every other rule still
applies, including approvals, safety and citing sources. If tutor mode is
on, its rules win where they differ.
</telegram_style>"""

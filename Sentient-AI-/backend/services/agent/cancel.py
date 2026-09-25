"""Keeps one "stop what you are doing" flag per user, for the kill switch.

Why it exists: computer_control checks this flag before every desktop action
and again just before input is sent, so a stop (Telegram /stop, the web Stop
button) takes effect between two clicks instead of after the turn. The runtime
clears a user's flag when their next turn starts. Nothing sets it yet: /stop
and the Stop button call ``request_cancel`` once they exist.

In-process only, like the browser sessions: it holds with a single uvicorn
worker. Guarded by a thread lock because the toolkit reads it from a worker
thread (``asyncio.to_thread``).
"""

from __future__ import annotations

import threading

_lock = threading.Lock()
_cancelled: set[str] = set()


def request_cancel(user_id: str) -> None:
    """Stop *user_id*'s running task: every later check says cancelled
    until ``clear``."""
    with _lock:
        _cancelled.add(str(user_id))


def is_cancelled(user_id: str) -> bool:
    """Whether *user_id* asked to stop and has not started a new turn since."""
    with _lock:
        return str(user_id) in _cancelled


def clear(user_id: str) -> None:
    """Lift *user_id*'s stop (a new turn starts). Clearing an unset flag
    is a no-op."""
    with _lock:
        _cancelled.discard(str(user_id))

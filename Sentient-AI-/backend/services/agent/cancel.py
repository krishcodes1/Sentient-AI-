"""Keeps each user's "stop what you are doing" requests, for the kill switch.

Why it exists: a stop (the web Stop button, Telegram /stop) must end any long
task promptly, not only a desktop one. Two readers check it:

- the agent runtime, at step boundaries: before every model round and before
  each tool call, so a browsing, search or multi-tool turn ends with a short
  "Stopped." reply instead of running on (``AgentRuntime._run_turn``);
- computer_control, before every desktop action and again just before input
  is sent, so a stop takes effect between two clicks.

Neither cuts a started tool call short.

A stop ends the work that was accepted before it, and nothing later. Every
piece of work takes a *mark* when it is accepted: a turn when its message
arrives (``mark``), an approved action when Approve is tapped. The work is
stopped once a stop is requested after its mark (``stopped_since``). Marks
and stops share one counter, so the order is exact. This is why nothing ever
clears a stop: a new message, or an Approve tap on any card, takes a fresh
mark for its own work and leaves a stop in force for a turn that is still
running. It also means a stop that lands after a message was accepted, while
its turn is still being set up, is not lost.

The runtime runs each turn and each approved action inside ``watching``, so
``is_cancelled`` (the computer toolkit's check, which has only a user id)
answers for the work in progress. The turn resumed after an approval uses
``mark_since`` with the time the card was raised: a stop pressed while the
card waited, or after the tap, ends it (the approved action itself still
runs, since the tap came after that stop).

Who requests a stop: ``POST /api/agent/stop`` (the web Stop button), and
Telegram /stop (``TelegramService._handle_stop``), which also cancels that
chat's running tasks outright. The two coexist: the runtime's checks end a
web turn gracefully with its "Stopped." reply, and the cancel ends the chat's
own turn at once, except that a tool call already started (or a card being
stored) finishes and is recorded first.

In-process only, like the browser sessions: it holds with a single uvicorn
worker, and the Telegram poller must run in the same process as the web
worker. Guarded by a thread lock because the toolkit reads it from a worker
thread (``asyncio.to_thread``, which carries the ``watching`` context).
"""

from __future__ import annotations

import itertools
import threading
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Iterator, NamedTuple, Optional


class _Stop(NamedTuple):
    """A user's latest stop request: its place in the shared order, and
    when it was made (compared with the time an approval card was raised)."""

    seq: int
    at: datetime


_lock = threading.Lock()
# One counter for marks and stops alike, so "was this stop after that
# mark" is a plain comparison. Only ever grows.
_order = itertools.count(1)
_last_stop: dict[str, _Stop] = {}
# Each user's newest mark: the answer ``is_cancelled`` gives outside any
# ``watching`` block ("asked to stop and has not started anything since").
_last_mark: dict[str, int] = {}
# The (user id, mark) of the turn or approved action running in this
# context, set by ``watching``.
_running: ContextVar[Optional[tuple[str, int]]] = ContextVar("agent_stop_running", default=None)


def request_cancel(user_id: str) -> None:
    """Stop *user_id*'s work in progress: everything accepted before now
    answers stopped at its next check. Work accepted later is not affected."""
    with _lock:
        _last_stop[str(user_id)] = _Stop(next(_order), datetime.now(timezone.utc))


def mark(user_id: str) -> int:
    """A mark for work *user_id* starts now (a message accepted, an Approve
    tap). Stops requested before it do not count against that work."""
    with _lock:
        value = next(_order)
        _last_mark[str(user_id)] = value
        return value


def mark_since(user_id: str, since: datetime) -> int:
    """A mark for work that has been waiting since *since* (an approval card
    raised then): a stop *user_id* requested after that moment counts
    against it, as does any later one. With no such stop this is ``mark``."""
    uid = str(user_id)
    with _lock:
        stop = _last_stop.get(uid)
        if stop is not None and stop.at > since:
            # Just before that stop, so it (and every later one) counts.
            return stop.seq - 1
        value = next(_order)
        _last_mark[uid] = value
        return value


def stopped_since(user_id: str, since_mark: int) -> bool:
    """Whether *user_id* requested a stop after *since_mark* was taken."""
    with _lock:
        stop = _last_stop.get(str(user_id))
        return stop is not None and stop.seq > since_mark


@contextmanager
def watching(user_id: str, since_mark: int) -> Iterator[None]:
    """Run a block as *user_id*'s work marked *since_mark*, so that
    ``is_cancelled`` inside it (and in threads and tasks it starts) answers
    for this work. The runtime wraps each turn and each approved action."""
    token = _running.set((str(user_id), since_mark))
    try:
        yield
    finally:
        _running.reset(token)


def is_cancelled(user_id: str) -> bool:
    """Whether *user_id*'s work in progress was stopped.

    Inside ``watching`` for this user: whether a stop came after that work's
    mark. Anywhere else: whether the user asked to stop and has not started
    anything since (their newest mark)."""
    uid = str(user_id)
    running = _running.get()
    if running is not None and running[0] == uid:
        return stopped_since(uid, running[1])
    with _lock:
        stop = _last_stop.get(uid)
        return stop is not None and stop.seq > _last_mark.get(uid, 0)


def clear(user_id: str) -> None:
    """Forget *user_id*'s stop entirely, for every piece of their work,
    running or not. The runtime never calls this (new work takes a fresh
    mark instead, which leaves a running turn stopped); it resets state
    between tests. Clearing an unset stop is a no-op."""
    with _lock:
        _last_stop.pop(str(user_id), None)

"""Holds the model a chat turn runs on, for tools that must use that same model
(video.transcript reads a YouTube video with the turn's own Gemini), and a
recorder that adds such a nested call's token usage to the turn.

Why it exists: a toolkit is dispatched by the executor with the arguments and
the user id only; it has no way to reach the provider the turn holds a lease
on. AgentRuntime._run_turn binds a TurnModel here for the length of the turn
(chat() restores whatever was bound before once the turn ends, however it
ends), so the toolkit reads ``current()`` and never builds a provider of its
own: no other provider, and no install key behind another provider, is ever
used. What the nested call costs is recorded into the turn's usage and its
spend meter, so the cost footer, the task cap and an unattended run's budget
all count it.

Stdlib only: the runtime imports this module.
"""

from __future__ import annotations

from contextvars import ContextVar, Token
from dataclasses import dataclass
from types import TracebackType
from typing import Any, Awaitable, Callable, Mapping, MutableMapping, Optional

# (url=..., start_s=..., end_s=..., fps=..., instruction=..., prompt=...,
# response_schema=..., max_output_tokens=...) -> the provider's response.
VideoReader = Callable[..., Awaitable[Any]]
UsageRecorder = Callable[[Mapping[str, int]], None]


@dataclass(frozen=True)
class TurnModel:
    """The turn's (provider, model) pair, the provider's video reader when
    it has one and the turn runs on Gemini (else None), and the recorder a
    nested model call reports its usage to. ``usd_left`` answers how much an
    unattended run may still spend (None: no run budget applies)."""

    provider: str
    model: str
    read_video_url: Optional[VideoReader]
    record_usage: UsageRecorder
    usd_left: Optional[Callable[[], float]] = None


class UsageMeter:
    """What the turn has cost so far, in USD, on the turn's own pricing
    (runtime.estimate_usd). A small mutable box, so a nested call recorded
    from a toolkit adds to the same figure the runtime's budget checks
    read."""

    __slots__ = ("usd",)

    def __init__(self) -> None:
        self.usd = 0.0

    def add(
        self, total_usage: MutableMapping[str, int], usage: Mapping[str, Any], usd: float
    ) -> None:
        """Add one call's token counts into *total_usage* (the turn's usage
        dict) and its estimated cost into the meter. Non-integer counts are
        ignored rather than trusted."""
        for key, value in usage.items():
            if isinstance(value, bool) or not isinstance(value, int):
                continue
            total_usage[key] = total_usage.get(key, 0) + value
        self.usd += max(0.0, float(usd))

    def left_of(self, cap: Optional[float]) -> Optional[Callable[[], float]]:
        """A reader of how much of *cap* (USD) is left as the meter runs;
        None when no cap applies."""
        if cap is None:
            return None
        limit = float(cap)
        return lambda: limit - self.usd


_current: ContextVar[Optional[TurnModel]] = ContextVar("turn_model", default=None)


def current() -> Optional[TurnModel]:
    """The TurnModel of the turn in progress; None outside a turn."""
    return _current.get()


def bind(model: TurnModel) -> Token[Optional[TurnModel]]:
    """Make *model* the current turn's. Returns the token ``reset`` takes."""
    return _current.set(model)


def reset(token: Token[Optional[TurnModel]]) -> None:
    _current.reset(token)


class bound:
    """``with bound(model):`` (or ``async with``) binds *model* for the
    block and restores the previous binding after it."""

    def __init__(self, model: TurnModel) -> None:
        self._model = model
        self._token: Optional[Token[Optional[TurnModel]]] = None

    def __enter__(self) -> TurnModel:
        self._token = _current.set(self._model)
        return self._model

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None:
        if self._token is not None:
            _current.reset(self._token)
            self._token = None

    async def __aenter__(self) -> TurnModel:
        return self.__enter__()

    async def __aexit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None:
        self.__exit__(exc_type, exc, tb)


class scope:
    """``async with scope():`` around a turn: whatever the turn binds (with
    ``bind``) is undone when the block ends, on success, on an error and on
    a cancel alike, so no binding outlives its turn."""

    def __init__(self) -> None:
        self._saved: Optional[TurnModel] = None

    def __enter__(self) -> None:
        self._saved = _current.get()

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None:
        _current.set(self._saved)

    async def __aenter__(self) -> None:
        self.__enter__()

    async def __aexit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None:
        self.__exit__(exc_type, exc, tb)


def video_reader_of(provider: Any, provider_name: str) -> Optional[VideoReader]:
    """The provider's ``read_video_url`` when the turn runs on Gemini and
    the provider has one; None otherwise (every other provider, and a
    stand-in without the method)."""
    if (provider_name or "").strip().lower() != "gemini":
        return None
    reader = getattr(provider, "read_video_url", None)
    return reader if callable(reader) else None


__all__ = [
    "TurnModel",
    "UsageMeter",
    "UsageRecorder",
    "VideoReader",
    "bind",
    "bound",
    "current",
    "reset",
    "scope",
    "video_reader_of",
]

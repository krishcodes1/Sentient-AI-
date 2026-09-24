"""Implements desktop.observe and desktop.act: the agent reads the front window
as an outline with refs, then clicks, types, presses keys, scrolls, opens apps
and switches windows through a ComputerBackend.

Why it exists: This is the most dangerous capability Crawler has, so every hard
rule lives here, between the model and the backend: the cancel flag, blocked
apps and key combos, secure (password) fields, payment forms, and "only the app
you last looked at". Static rules run before the backend is called at all; the
rules that need live facts read the screen first and still refuse before any
input is sent. Every failure comes back as a result, never an exception.

Results (spec §3):

- observe outline → ``{ok, frontmost_app, app, window_title, outline: [lines],
  refs: int, truncated, secure_fields_redacted[, image | image_error]}``
- observe apps → ``{ok, frontmost_app, window_title, apps: [{name, pid, active}]}``
- observe windows → ``{ok, frontmost_app, window_title, windows: [{app, title, index}]}``
- act → ``{ok: True, did: "click button \\"Send\\" in Mail", then: <outline result>}``
- refusal → ``{ok: False, refused: True, rule, error}``; other failures
  ``{ok: False, error[, stale_ref | needs_observe | needs_permission]}``.

Refs (``d1``, ``d2`` …) belong to one user and last until that user's next
outline, which every observe outline and every act's ``then`` produces.
Numbering carries on across outlines, so a stale ref is refused as unknown
instead of silently naming a different element.
"""

from __future__ import annotations

import asyncio
import dataclasses
import re
import threading
import unicodedata
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Optional

import structlog

from services.tools.computer import keys as keymod
from services.tools.computer import rules
from services.tools.computer.backend import (
    AppNotFoundError,
    BackendUnavailableError,
    BlockedTargetError,
    ComputerBackend,
    CoveredTargetError,
    ElementGoneError,
    ElevatedTargetError,
    KeyCombo,
    Node,
    Point,
    SecureTargetError,
)
from services.tools.computer.outline import (
    DEFAULT_MAX_CHARS,
    MAX_CHARS_LIMIT,
    MIN_MAX_CHARS,
    build_outline,
    clean_text,
)

logger = structlog.get_logger(__name__)

CancelFlag = Callable[[str], bool]
# Returns a JPEG/PNG data URL of the screen for the model, or None.
ImageSource = Callable[[], Optional[str]]

MAX_TEXT_CHARS = 2000
SCROLL_AMOUNT = 5
MAX_NODES = 3000
MAX_LIST_ITEMS = 100
MAX_COORD = 100_000
MAX_WINDOW_INDEX = 50
_CHECK_MAX_CHARS = 200_000
_CHECK_MAX_LINES = 5000
# Web content in a browser nests deeply; the payment scan must reach it.
_CHECK_MAX_DEPTH = 200
_LABEL_CHARS = 60
_LOG_DETAIL_CHARS = 200

OBSERVE_ACTIONS: tuple[str, ...] = ("outline", "apps", "windows")
ACT_ACTIONS: tuple[str, ...] = (
    "click",
    "double_click",
    "type",
    "key",
    "scroll",
    "open_app",
    "focus_window",
)
_OBSERVE_PARAMS = frozenset({"action", "app", "max_chars", "for_model_image"})
_ACT_PARAMS: dict[str, frozenset[str]] = {
    "click": frozenset({"action", "ref", "x", "y"}),
    "double_click": frozenset({"action", "ref", "x", "y"}),
    "type": frozenset({"action", "text", "ref"}),
    "key": frozenset({"action", "keys"}),
    "scroll": frozenset({"action", "direction"}),
    "open_app": frozenset({"action", "app"}),
    "focus_window": frozenset({"action", "app", "index"}),
}
_APP_ACTIONS = frozenset({"open_app", "focus_window"})
_REF = re.compile(r"d[1-9]\d{0,8}")
# An app's name, not a path, URL or command-line flag.
_APP_NAME = re.compile(r"(?![.\-])[\w .&'()+,!\-]{1,100}")

_UNAVAILABLE = "Controlling this computer is not available here"
_NO_PERMISSION = (
    "The operating system has not given Crawler permission to control this computer "
    "(Accessibility). The owner can grant it in Settings → Permissions."
)
_OWNER_STEP = "The owner can do this step themselves."


class _Refused(Exception):
    """A hard rule said no. Audited with its rule name."""

    def __init__(self, rule: str, message: str) -> None:
        super().__init__(message)
        self.rule = rule
        self.message = message


class _Failed(Exception):
    """An ordinary failure whose message is safe to show the model."""

    def __init__(self, message: str, **extra: Any) -> None:
        super().__init__(message)
        self.message = message
        self.extra = extra


@dataclass(frozen=True)
class _Snapshot:
    """What the user's latest outline showed: its app and its refs."""

    app: str
    window_title: str
    refs: Mapping[str, Node]


@dataclass
class _UserState:
    next_ref: int = 1
    snapshot: Optional[_Snapshot] = None


@dataclass(frozen=True)
class _Request:
    """One validated desktop.act call."""

    action: str
    ref: Optional[str] = None
    node: Optional[Node] = None
    point: Optional[Point] = None
    text: str = ""
    combo: Optional[KeyCombo] = None
    direction: str = ""
    app: str = ""
    index: int = 0


def _error(message: str, **extra: Any) -> dict[str, Any]:
    return {"ok": False, "error": message, **extra}


def _log_failure(event: str, exc: BaseException, **fields: Any) -> None:
    logger.warning(
        event,
        error_type=type(exc).__name__,
        error=str(exc)[:_LOG_DETAIL_CHARS],
        **fields,
    )


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _label(text: object) -> str:
    """Untrusted text (an app or element name) made safe for one line of an
    approval card or a result sentence."""
    return clean_text(text, _LABEL_CHARS).replace('"', "'")


def _safe_action(value: object) -> str:
    return value if isinstance(value, str) and value in ACT_ACTIONS + OBSERVE_ACTIONS else "?"


def _check_keys(params: Mapping[str, Any], allowed: frozenset[str], tool: str) -> None:
    unknown = sorted(clean_text(k, 30) for k in params if k not in allowed)
    if unknown:
        raise _Failed(
            f"{tool} does not take {', '.join(unknown)} (it takes: {', '.join(sorted(allowed))})."
        )


def _app_arg(value: Any, what: str) -> str:
    if not isinstance(value, str) or not _APP_NAME.fullmatch(value.strip()):
        raise _Failed(f"{what} must be an app's name, such as 'TextEdit' (not a path or a URL).")
    return value.strip()


def _ref_arg(value: Any) -> str:
    if not isinstance(value, str) or not _REF.fullmatch(value.strip()):
        raise _Failed("ref must look like 'd12' (a ref from desktop.observe).")
    return value.strip()


def _coord(value: Any, name: str) -> int:
    if not _is_int(value) or not 0 <= value <= MAX_COORD:
        raise _Failed(f"{name} must be a whole number of screen points, 0 or more (main display).")
    return int(value)


def _max_chars(value: Any) -> int:
    if value is None:
        return DEFAULT_MAX_CHARS
    if not _is_int(value):
        raise _Failed(f"max_chars must be a whole number (at most {MAX_CHARS_LIMIT}).")
    return max(MIN_MAX_CHARS, min(int(value), MAX_CHARS_LIMIT))


def _parse_act(params: Mapping[str, Any]) -> _Request:
    """Validate a desktop.act call's arguments. Touches nothing."""
    action = params.get("action")
    if not isinstance(action, str) or action not in ACT_ACTIONS:
        raise _Failed(f"action must be one of: {', '.join(ACT_ACTIONS)}.")
    _check_keys(params, _ACT_PARAMS[action], f"desktop.act {action}")
    if action in ("click", "double_click"):
        ref, x, y = params.get("ref"), params.get("x"), params.get("y")
        if ref is not None:
            if x is not None or y is not None:
                raise _Failed("Give either ref or x and y, not both.")
            return _Request(action, ref=_ref_arg(ref))
        if x is None or y is None:
            raise _Failed(
                f"{action} needs a ref from desktop.observe (or x and y when no ref exists)."
            )
        return _Request(action, point=(_coord(x, "x"), _coord(y, "y")))
    if action == "type":
        text = params.get("text")
        if not isinstance(text, str) or not text:
            raise _Failed(f"type needs text (1 to {MAX_TEXT_CHARS} characters).")
        if len(text) > MAX_TEXT_CHARS:
            raise _Failed(f"text is too long ({len(text)} characters; at most {MAX_TEXT_CHARS}).")
        if any(unicodedata.category(ch) == "Cc" and ch not in "\n\t" for ch in text):
            raise _Failed("text may not contain control characters other than newlines and tabs.")
        ref = params.get("ref")
        return _Request(action, text=text, ref=_ref_arg(ref) if ref is not None else None)
    if action == "key":
        try:
            combo = keymod.parse_combo(params.get("keys"))
        except keymod.BlockedKeyError as exc:
            raise _Refused("blocked_key", f"{exc} {_OWNER_STEP}")
        except keymod.KeyComboError as exc:
            raise _Failed(str(exc))
        return _Request(action, combo=combo)
    if action == "scroll":
        direction = params.get("direction")
        if direction not in ("up", "down"):
            raise _Failed("scroll needs direction 'up' or 'down'.")
        return _Request(action, direction=str(direction))
    app = _app_arg(params.get("app"), "app")
    index = params.get("index", 0) if action == "focus_window" else 0
    if not _is_int(index) or not 0 <= index <= MAX_WINDOW_INDEX:
        raise _Failed(
            f"index must be a whole number from 0 (the app's front window) to {MAX_WINDOW_INDEX}."
        )
    return _Request(action, app=app, index=int(index))


def _blocked_message(app: str) -> str:
    return (
        f"Crawler never acts in {app}. Password managers, terminals, system settings, the "
        f"login screen and Crawler itself are off limits. {_OWNER_STEP}"
    )


_SECURE_MESSAGE = f"That is a password field, and Crawler never types into one. {_OWNER_STEP}"


def _characters(count: int) -> str:
    return "1 character" if count == 1 else f"{count} characters"


def _target(node: Node, with_role: bool) -> str:
    role = clean_text(node.role, 30).lower() or "element"
    name = _label(node.name)
    if name:
        return f'{role} "{name}"' if with_role else f'"{name}"'
    return f"the {role}"


def _facts(request: _Request, app: Optional[str], *, with_role: bool) -> str:
    """What the request does, from facts only (the element's real name and
    role, the app the outline came from, the parsed combo, the character
    count), never from the model's own wording."""
    where = f" in {_label(app)}" if app else " in the frontmost app"
    action = request.action
    stale = "(not in the latest outline, so it will be refused)"
    if action in ("click", "double_click"):
        verb = "click" if action == "click" else "double-click"
        if request.ref is not None:
            if request.node is None:
                return f"{verb} {request.ref} {stale}"
            return f"{verb} {_target(request.node, with_role)}{where}"
        x, y = request.point or (0, 0)
        return f"{verb} at ({x}, {y}){where}"
    if action == "type":
        amount = _characters(len(request.text))
        breaks = request.text.count("\n")
        if breaks:
            amount += f" (including {breaks} line break{'' if breaks == 1 else 's'})"
        if request.ref is not None:
            if request.node is None:
                return f"type {amount} into {request.ref} {stale}"
            return f"type {amount} into {_target(request.node, with_role)}{where}"
        return f"type {amount} into the focused field{where}"
    if action == "key":
        return f"press {request.combo}{where}"
    if action == "scroll":
        return f"scroll {request.direction}{where}"
    if action == "open_app":
        return f"open {_label(request.app)}"
    suffix = f" window {request.index}" if request.index else ""
    return f"switch to {_label(request.app)}{suffix}"


def _find_handle(nodes: Iterable[Node], handle: Any) -> Optional[Node]:
    if handle is None:
        return None
    stack = list(nodes)
    while stack:
        node = stack.pop()
        try:
            if node.handle is not None and node.handle == handle:
                return node
        except Exception:  # a backend handle that cannot be compared is no match
            pass
        stack.extend(node.children or ())
    return None


class ComputerToolkit:
    """desktop.observe / desktop.act over one ComputerBackend.

    ``cancel_flag(user_id)`` is True once the user's turn was stopped
    (``/stop``, the web Stop button); it is checked before every action and
    again just before any input is sent. A flag that raises counts as set.
    ``image_source`` (optional) supplies ``for_model_image`` screenshots;
    whoever wires it is responsible for the ``screen`` capability's gate.
    """

    def __init__(
        self,
        backend: ComputerBackend,
        *,
        cancel_flag: CancelFlag,
        image_source: Optional[ImageSource] = None,
    ) -> None:
        self._backend = backend
        self._cancel_flag = cancel_flag
        self._image_source = image_source
        # One desktop: operations run one at a time, whoever asks.
        self._op_lock = threading.Lock()
        # Guards _users only, so describe() never waits for a slow backend call.
        self._state_lock = threading.Lock()
        self._users: dict[str, _UserState] = {}

    # ── public surface ──────────────────────────────────────────────────

    async def execute(
        self,
        action_family: str,
        params: Optional[Mapping[str, Any]],
        *,
        user_id: str,
    ) -> dict[str, Any]:
        """Run ``desktop.observe`` or ``desktop.act``. Never raises."""
        return await asyncio.to_thread(self._execute, action_family, params, user_id)

    def describe(
        self, params: Optional[Mapping[str, Any]], *, user_id: Optional[str] = None
    ) -> str:
        """The approval-card sentence for a desktop.act call, built from facts:
        ``Click "Send" in Mail``, ``Type 42 characters into "Subject" in Mail``,
        ``Press cmd+s in TextEdit``, ``Open Calculator``. Refs resolve against
        *user_id*'s latest outline. Calls no backend."""
        try:
            request = _parse_act(dict(params or {}))
        except _Refused as refusal:
            return f"Blocked desktop action: {refusal.message}"
        except _Failed as failure:
            return f"Invalid desktop action: {failure.message}"
        except Exception:
            return "Invalid desktop action."
        snapshot = self._snapshot(user_id) if user_id else None
        if request.ref is not None and snapshot is not None:
            request = dataclasses.replace(request, node=snapshot.refs.get(request.ref))
        text = _facts(request, snapshot.app if snapshot else None, with_role=False)
        return text[:1].upper() + text[1:]

    def precheck(
        self, params: Optional[Mapping[str, Any]], *, user_id: str
    ) -> Optional[dict[str, Any]]:
        """The refusal or error a desktop.act call would get from the checks
        that need no backend (arguments, cancel flag, blocked apps and combos,
        typing into a known password field, stale refs), or None. Lets the
        caller refuse before showing an approval card."""
        try:
            request = _parse_act(dict(params or {}))
            self._check_cancel(user_id)
            self._static_rules(request, self._snapshot(user_id))
        except _Refused as refusal:
            return {"ok": False, "refused": True, "rule": refusal.rule, "error": refusal.message}
        except _Failed as failure:
            return _error(failure.message, **failure.extra)
        except Exception as exc:
            _log_failure("computer_precheck_failed", exc)
            return _error("desktop.act failed.")
        return None

    # ── dispatch ────────────────────────────────────────────────────────

    def _execute(self, family: str, params: Any, user_id: str) -> dict[str, Any]:
        if family not in ("observe", "act"):
            return _error(f"Unknown desktop tool '{clean_text(family, 40)}'.")
        if not isinstance(user_id, str) or not user_id:
            return _error("desktop tools need a signed-in user.")
        if params is None:
            params = {}
        if not isinstance(params, Mapping):
            return _error(f"Invalid arguments for desktop.{family}.")
        params = dict(params)
        action = params.get("action")
        try:
            with self._op_lock:
                if family == "observe":
                    return self._observe(params, user_id)
                return self._act(params, user_id)
        except _Refused as refusal:
            logger.info(
                "computer_refused",
                tool=f"desktop.{family}",
                action=_safe_action(action),
                rule=refusal.rule,
                user_id=user_id,
            )
            return {"ok": False, "refused": True, "rule": refusal.rule, "error": refusal.message}
        except _Failed as failure:
            return _error(failure.message, **failure.extra)
        except Exception as exc:  # last resort: never raise into the agent loop
            _log_failure(
                "computer_action_failed", exc, tool=f"desktop.{family}", action=_safe_action(action)
            )
            return _error(f"desktop.{family} failed.")

    # ── per-user state ──────────────────────────────────────────────────

    def _state(self, user_id: str) -> _UserState:
        with self._state_lock:
            return self._users.setdefault(user_id, _UserState())

    def _snapshot(self, user_id: Optional[str]) -> Optional[_Snapshot]:
        if not user_id:
            return None
        with self._state_lock:
            state = self._users.get(user_id)
            return state.snapshot if state else None

    def _forget(self, user_id: str) -> None:
        with self._state_lock:
            state = self._users.get(user_id)
            if state is not None:
                state.snapshot = None

    # ── shared checks ───────────────────────────────────────────────────

    def _check_cancel(self, user_id: str) -> None:
        try:
            cancelled = bool(self._cancel_flag(user_id))
        except Exception as exc:  # no answer is not a "carry on"
            _log_failure("computer_cancel_flag_failed", exc)
            cancelled = True
        if cancelled:
            raise _Refused("cancelled", "Stopped: this task was cancelled, so nothing was done.")

    def _preflight(self) -> None:
        try:
            ok, reason = self._backend.available()
        except Exception as exc:
            _log_failure("computer_available_failed", exc)
            ok, reason = False, ""
        if not ok:
            raise _Failed(f"{_UNAVAILABLE}: {reason}" if reason else f"{_UNAVAILABLE}.")
        try:
            state = self._backend.permission()
        except Exception as exc:  # fail closed: no answer is not a grant
            _log_failure("computer_permission_failed", exc)
            state = "denied"
        if state == "denied":
            raise _Failed(_NO_PERMISSION, needs_permission=True)

    def _frontmost(self) -> tuple[str, str]:
        try:
            app, title = self._backend.frontmost()
        except BackendUnavailableError:
            raise _Failed(f"{_UNAVAILABLE}.")
        except Exception as exc:
            _log_failure("computer_frontmost_failed", exc)
            return "", ""
        return str(app or ""), str(title or "")

    def _read_tree(self, app: str) -> list[Node]:
        try:
            return list(self._backend.outline(app, MAX_NODES) or [])
        except AppNotFoundError:
            raise _Failed(f"No running app named '{_label(app)}'.")
        except BackendUnavailableError:
            raise _Failed(f"{_UNAVAILABLE}.")

    # ── observe ─────────────────────────────────────────────────────────

    def _observe(self, params: dict[str, Any], user_id: str) -> dict[str, Any]:
        _check_keys(params, _OBSERVE_PARAMS, "desktop.observe")
        action = params.get("action")
        if action not in OBSERVE_ACTIONS:
            raise _Failed(f"action must be one of: {', '.join(OBSERVE_ACTIONS)}.")
        app = params.get("app")
        if app is not None:
            app = _app_arg(app, "app")
        max_chars = _max_chars(params.get("max_chars"))
        for_image = params.get("for_model_image", False)
        if not isinstance(for_image, bool):
            raise _Failed("for_model_image must be true or false.")
        self._check_cancel(user_id)
        self._preflight()
        if action == "apps":
            return self._apps()
        if action == "windows":
            return self._windows(app)
        result = self._outline(user_id, app=app, max_chars=max_chars)
        if for_image:
            self._attach_image(result)
        return result

    def _apps(self) -> dict[str, Any]:
        apps = list(self._backend.list_apps())
        front_app, title = self._frontmost()
        items: list[dict[str, Any]] = []
        for info in apps[:MAX_LIST_ITEMS]:
            item: dict[str, Any] = {
                "name": _label(info.name),
                "pid": int(info.pid),
                "active": bool(info.active),
            }
            if info.elevated:
                item["elevated"] = True
            items.append(item)
        result: dict[str, Any] = {
            "ok": True,
            "frontmost_app": _label(front_app),
            "window_title": self._title(front_app, title),
            "apps": items,
        }
        if len(apps) > MAX_LIST_ITEMS:
            result["truncated"] = True
        if any(item.get("elevated") for item in items):
            result["note"] = (
                "Apps marked elevated run as administrator; Windows does not let Crawler act in them."
            )
        return result

    def _windows(self, app: Optional[str]) -> dict[str, Any]:
        windows = list(self._backend.list_windows())
        if app is not None:
            windows = [w for w in windows if rules.same_app(w.app, app)]
        front_app, title = self._frontmost()
        items = [
            {"app": _label(w.app), "title": self._title(w.app, w.title), "index": int(w.index)}
            for w in windows[:MAX_LIST_ITEMS]
        ]
        result: dict[str, Any] = {
            "ok": True,
            "frontmost_app": _label(front_app),
            "window_title": self._title(front_app, title),
            "windows": items,
        }
        if len(windows) > MAX_LIST_ITEMS:
            result["truncated"] = True
        return result

    def _running_app(self, app: str) -> str:
        """The backend's own name for the running app *app* names, so the
        refs, results and approval cards carry the app's real name rather
        than the model's spelling of it."""
        if rules.secret_app(app):
            return app  # refused by the caller; nothing to look up
        for info in self._backend.list_apps():
            if rules.same_app(info.name, app):
                return str(info.name)
        raise _Failed(f"No running app named '{_label(app)}'.")

    @staticmethod
    def _title(app: str, title: str) -> str:
        # A password manager's window title can name the item on show.
        return "" if rules.secret_app(app) else clean_text(title, 120)

    def _outline(self, user_id: str, *, app: Optional[str], max_chars: int) -> dict[str, Any]:
        """Outline *app* (the frontmost app when None) and make its refs the
        user's current ones. The old refs are dropped first, so a failure
        here leaves the user with none rather than stale ones."""
        state = self._state(user_id)
        with self._state_lock:
            state.snapshot = None
            ref_start = state.next_ref
        front_app, front_title = self._frontmost()
        if app is None:
            target = front_app
        elif rules.same_app(app, front_app):
            target = front_app
        else:
            target = self._running_app(app)
        if not target:
            raise _Failed("Could not tell which app is in front; name one with app.")
        secret = rules.secret_app(target) or (rules.secret_app(app) if app else None)
        if secret:
            raise _Refused(
                "secret_app",
                f"{secret} holds passwords, so Crawler does not read its windows. {_OWNER_STEP}",
            )
        nodes = self._read_tree(target)
        out = build_outline(nodes, max_chars=max_chars, ref_start=ref_start)
        if rules.same_app(target, front_app):
            title = front_title
        else:
            title = nodes[0].name if nodes and nodes[0].role == "window" else ""
        with self._state_lock:
            state.next_ref = out.next_ref
            state.snapshot = _Snapshot(app=target, window_title=title, refs=dict(out.refs))
        return {
            "ok": True,
            "frontmost_app": _label(front_app),
            "app": _label(target),
            "window_title": clean_text(title, 120),
            "outline": list(out.lines),
            "refs": len(out.refs),
            "truncated": out.truncated,
            "secure_fields_redacted": out.secure_fields_redacted,
        }

    def _attach_image(self, result: dict[str, Any]) -> None:
        if self._image_source is None:
            result["image_error"] = "Screenshots are not available to this tool here."
            return
        try:
            image = self._image_source()
        except Exception as exc:
            _log_failure("computer_image_failed", exc)
            image = None
        if isinstance(image, str) and image.startswith("data:image/"):
            result["image"] = image
        else:
            result["image_error"] = "Could not take a screenshot."

    # ── act ─────────────────────────────────────────────────────────────

    def _act(self, params: dict[str, Any], user_id: str) -> dict[str, Any]:
        request = _parse_act(params)
        self._check_cancel(user_id)
        snapshot = self._snapshot(user_id)
        # Static rules: no backend call of any kind before these pass.
        request = self._static_rules(request, snapshot)
        self._preflight()
        if request.action not in _APP_ACTIONS:
            assert snapshot is not None  # _static_rules refuses input without one
            self._live_rules(request, snapshot)
        # The last word before input is sent: the user may have hit Stop
        # while the screen was being checked.
        self._check_cancel(user_id)
        self._perform(request, user_id)
        did = _facts(request, snapshot.app if snapshot else None, with_role=True)
        return {"ok": True, "did": did, "then": self._then(user_id)}

    def _static_rules(self, request: _Request, snapshot: Optional[_Snapshot]) -> _Request:
        """Rules decided from the request and the user's last outline alone."""
        if request.action in _APP_ACTIONS:
            blocked = rules.blocked_app(request.app)
            if blocked:
                raise _Refused("blocked_app", _blocked_message(blocked))
            return request
        if snapshot is None:
            raise _Failed(
                "Look first: call desktop.observe, then act on what it shows.",
                needs_observe=True,
            )
        blocked = rules.blocked_app(snapshot.app)
        if blocked:
            raise _Refused("blocked_app", _blocked_message(blocked))
        if rules.crawler_window(snapshot.window_title):
            raise _Refused("blocked_app", _blocked_message("Crawler AI"))
        node = None
        if request.ref is not None:
            node = snapshot.refs.get(request.ref)
            if node is None:
                raise _Failed(
                    f"{request.ref} is not in the latest outline (refs last until the next "
                    "outline). Call desktop.observe again.",
                    stale_ref=True,
                )
        if request.action == "type" and node is not None and rules.looks_secure(node):
            raise _Refused("secure_field", _SECURE_MESSAGE)
        if request.combo is not None:
            reason = keymod.blocked_reason(request.combo, snapshot.app)
            if reason:
                raise _Refused(
                    "blocked_key", f"{reason}, so Crawler never presses it. {_OWNER_STEP}"
                )
        return dataclasses.replace(request, node=node)

    def _live_rules(self, request: _Request, snapshot: _Snapshot) -> None:
        """Rules that need the screen as it is now. They read (frontmost app,
        focused element, the target window) and send no input. The front app
        is checked first and again last: the window scan in between can take
        seconds, and input goes to whatever is in front when it is sent."""
        self._check_front(snapshot)
        self._check_window(request, snapshot)
        self._check_front(snapshot)

    def _check_front(self, snapshot: _Snapshot) -> None:
        front_app, front_title = self._frontmost()
        if not front_app:
            raise _Refused(
                "unknown_app", "Could not tell which app is in front, so nothing was done."
            )
        blocked = rules.blocked_app(front_app)
        if blocked:
            raise _Refused("blocked_app", _blocked_message(blocked))
        # Crawler's own web UI in a browser: acting there could approve its
        # own approval cards.
        if rules.crawler_window(front_title):
            raise _Refused("blocked_app", _blocked_message("Crawler AI"))
        if not rules.same_app(front_app, snapshot.app):
            raise _Refused(
                "frontmost_changed",
                f"{_label(front_app)} is in front now, not {_label(snapshot.app)} (the app the "
                f"latest outline showed), so nothing was done. Call desktop.observe again, or "
                f"focus_window to bring {_label(snapshot.app)} back.",
            )

    def _check_window(self, request: _Request, snapshot: _Snapshot) -> None:
        typing = (request.action == "type" and request.node is None) or (
            request.combo is not None and keymod.enters_text(request.combo)
        )
        if typing:
            try:
                focused = self._backend.focused()
            except Exception as exc:
                _log_failure("computer_focused_failed", exc)
                focused = None
            if focused is None:
                raise _Refused(
                    "focus_unknown",
                    "Could not tell which field has keyboard focus, so nothing was typed. "
                    "Call desktop.observe and pass the field's ref.",
                )
            if rules.looks_secure(focused):
                raise _Refused("secure_field", _SECURE_MESSAGE)
        try:
            nodes = list(self._backend.outline(snapshot.app, MAX_NODES) or [])
        except Exception as exc:  # cannot check for payment fields: do nothing
            _log_failure("computer_check_failed", exc)
            raise _Refused(
                "check_failed",
                "Could not read the window to check it before acting, so nothing was done.",
            )
        scan = build_outline(
            nodes,
            max_chars=_CHECK_MAX_CHARS,
            max_lines=_CHECK_MAX_LINES,
            max_depth=_CHECK_MAX_DEPTH,
            include_hidden=True,
        )
        reason = rules.payment_reason(scan.lines)
        if reason:
            raise _Refused(
                "payment",
                f"The {_label(snapshot.app)} window shows {reason}. Crawler never enters or "
                f"submits payment details. {_OWNER_STEP}",
            )
        if request.action == "type" and request.node is not None:
            live = _find_handle(nodes, request.node.handle)
            if live is not None and rules.looks_secure(live):
                raise _Refused("secure_field", _SECURE_MESSAGE)
        if request.point is not None:
            window = nodes[0] if nodes else None
            if window is None or not window.contains(request.point):
                x, y = request.point
                raise _Refused(
                    "outside_window",
                    f"({x}, {y}) is outside the {_label(snapshot.app)} window, so nothing was "
                    "clicked. Use a ref from desktop.observe, or a point inside the window.",
                )

    def _perform(self, request: _Request, user_id: str) -> None:
        backend = self._backend
        action = request.action
        try:
            if action in ("click", "double_click"):
                target = request.node if request.node is not None else request.point
                assert target is not None
                backend.click(target, double=action == "double_click")
            elif action == "type":
                backend.type_text(request.text, request.node)
            elif action == "key":
                assert request.combo is not None
                backend.key(request.combo)
            elif action == "scroll":
                backend.scroll(request.direction, SCROLL_AMOUNT)
            elif action == "open_app":
                backend.open_app(request.app)
            else:
                backend.focus_window(request.app, request.index)
        # The backend's own hard-rule checks (defence in depth): it saw what
        # the toolkit could not (a localized or executable name that is a
        # blocked app, focus landing on a password field mid-typing, another
        # app's window over the click point). Refusals, in the toolkit's words.
        except BlockedTargetError as exc:
            self._forget(user_id)
            raise _Refused("blocked_app", _blocked_message(_label(exc.app) or "that app"))
        except SecureTargetError:
            self._forget(user_id)
            raise _Refused(
                "secure_field",
                "The field with keyboard focus is a password field (or Crawler could not tell "
                "which field has focus), so Crawler stopped typing: it never types into "
                f"password fields. {_OWNER_STEP} Call desktop.observe to see what was entered.",
            )
        except CoveredTargetError:
            self._forget(user_id)
            raise _Refused(
                "covered",
                "Another app's window covers that spot (or Crawler could not tell whose "
                "window it is), so nothing was clicked. Call desktop.observe again.",
            )
        except ElementGoneError:
            self._forget(user_id)
            raise _Failed(
                "That element is no longer on screen. Call desktop.observe again.", stale_ref=True
            )
        except AppNotFoundError:
            self._forget(user_id)
            if action not in _APP_ACTIONS:
                raise _Failed(
                    "That app is no longer running. Call desktop.observe again.", stale_ref=True
                )
            what = f"window {request.index} of " if action == "focus_window" else ""
            raise _Failed(f"Could not find {what}an app named '{_label(request.app)}'.")
        except ElevatedTargetError:
            self._forget(user_id)
            raise _Failed(
                "That window runs as administrator, and Windows does not let Crawler control it. "
                + _OWNER_STEP
            )
        except BackendUnavailableError:
            raise _Failed(f"{_UNAVAILABLE}.")
        except Exception as exc:
            self._forget(user_id)
            _log_failure("computer_act_failed", exc, action=action)
            raise _Failed(
                f"desktop.act {action} failed; it may or may not have taken effect. "
                "Call desktop.observe to check."
            )

    def _then(self, user_id: str) -> dict[str, Any]:
        """The fresh outline an act returns. The act already happened, so a
        failure here is reported inside ``then`` and never as the act's."""
        try:
            return self._outline(user_id, app=None, max_chars=DEFAULT_MAX_CHARS)
        except _Refused as refusal:
            return {"ok": False, "withheld": True, "error": refusal.message}
        except _Failed as failure:
            return _error(failure.message)
        except Exception as exc:
            self._forget(user_id)
            _log_failure("computer_then_failed", exc)
            return _error("Could not read the screen after the action; call desktop.observe.")

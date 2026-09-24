"""Built-in system tools: report and install optional capabilities.

The product runs on the user's own machine (or in their Docker
container). Some tools need software that is deliberately not shipped
with the backend — today the Chromium browser behind ``web.screenshot``,
a download most installs never want. When such a tool reports the gap,
the agent can offer to close it. Three constraints shape the module:

- **Allowlist.** The model picks a capability *name*; everything else —
  the pip requirement, the browser to download, every argv — is fixed in
  :data:`ALLOWLIST` at import time. Nothing the model supplies reaches a
  subprocess, so "install this package" is not a request the agent can
  carry out, however it is phrased.
- **Approval.** Installing changes the host. ``install_capability`` is a
  WRITE the permission engine routes through the human approval flow
  (the card the user sees on the web or Telegram), and the executor
  refuses to run it without that approval, so the model can never
  install unasked. Reading what is installed is free.
- **Bounds.** Steps run without a shell, under one deadline for the
  whole install, and only the tail of their output comes back: the user
  pays per token for tool output, and a pip log is unbounded.

Detection is a filesystem check, not a browser launch. Launching Chromium
to see whether it exists takes seconds and a driver process; instead the
check mirrors what Playwright itself consults at launch: the package must
be importable, and the browser builds its bundled ``browsers.json`` names
(``chromium-<revision>`` and, on releases that have it,
``chromium_headless_shell-<revision>``) must each be present under the
browsers directory — ``PLAYWRIGHT_BROWSERS_PATH`` when set (``0`` meaning
inside the package), else the platform cache Playwright defaults to —
with the ``INSTALLATION_COMPLETE`` marker Playwright writes only after a
finished download. Pinning to the manifest's revision is deliberate: a
Chromium left over from an older Playwright would pass a looser check and
then fail at launch, and the install steps are idempotent, so a false
"missing" costs a quick no-op re-run while a false "installed" would
strand the user.

Tool errors are results, not exceptions — the model has to read what went
wrong and try again.
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib.util
import inspect
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Optional

import structlog

if TYPE_CHECKING:
    from services.capabilities.base import CapabilityStatus

logger = structlog.get_logger(__name__)

# One deadline for the whole install, all steps included.
INSTALL_TIMEOUT_S = 10 * 60.0
# How much subprocess output is handed back to the model.
_LOG_TAIL_CHARS = 2048

# Playwright writes this file into a browser directory once the download
# has been unpacked; a directory without it is a partial install.
_INSTALL_MARKER = "INSTALLATION_COMPLETE"
# The browsers.json entries a headless ``chromium.launch()`` needs.
# Older manifests list only "chromium"; newer ones add the headless shell
# and launch it by default, so both must be present when both are listed.
_CHROMIUM_BUILDS = ("chromium", "chromium-headless-shell")

StepRunner = Callable[[list[str], float], Awaitable[tuple[int, str]]]


@dataclass(frozen=True)
class Installable:
    """One installable component in :data:`ALLOWLIST` (not to be confused
    with ``services.capabilities.Capability``, the owner's on/off switch).
    ``steps`` are complete argv lists run with no shell; nothing is ever
    interpolated into them."""

    description: str
    size_hint: str
    steps: tuple[tuple[str, ...], ...]
    detect: Callable[[], bool]


def browser_installed() -> bool:
    """True when Playwright and the Chromium build(s) it would launch are
    both present. See the module docstring for what is checked and why."""
    package_dir = _playwright_package_dir()
    if package_dir is None:
        return False
    browsers_path = _browsers_path(package_dir)
    required = _required_chromium_dirs(package_dir)
    if required is None:
        # No readable manifest: fall back to "some complete Chromium build
        # exists", which is the best a filesystem check can do here.
        return any(
            (candidate / _INSTALL_MARKER).is_file()
            for candidate in browsers_path.glob("chromium-*")
        )
    return all((browsers_path / name / _INSTALL_MARKER).is_file() for name in required)


def _playwright_package_dir() -> Optional[Path]:
    # find_spec locates the package without executing it, which keeps the
    # check cheap and side-effect free.
    try:
        spec = importlib.util.find_spec("playwright")
    except (ImportError, ValueError):
        return None
    if spec is None or not spec.origin:
        return None
    return Path(spec.origin).parent


def _browsers_path(package_dir: Path) -> Path:
    """Where Playwright keeps downloaded browsers, resolved the way its own
    registry does."""
    configured = os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "").strip()
    if configured == "0":
        return package_dir / "driver" / "package" / ".local-browsers"
    if configured:
        return Path(configured).expanduser()
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Caches" / "ms-playwright"
    if sys.platform.startswith("win"):
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "ms-playwright"
    xdg = os.environ.get("XDG_CACHE_HOME")
    return (Path(xdg) if xdg else Path.home() / ".cache") / "ms-playwright"


def _required_chromium_dirs(package_dir: Path) -> Optional[list[str]]:
    """Directory names of the Chromium builds this Playwright launches, from
    its bundled manifest. None when the manifest cannot be read."""
    manifest = package_dir / "driver" / "package" / "browsers.json"
    try:
        entries = json.loads(manifest.read_text("utf-8")).get("browsers", [])
    except (OSError, ValueError, AttributeError):
        return None
    names = [
        # Playwright names the directory after the build with dashes turned
        # to underscores: chromium-headless-shell -> chromium_headless_shell.
        f"{entry['name'].replace('-', '_')}-{entry['revision']}"
        for entry in entries
        if isinstance(entry, dict)
        and entry.get("name") in _CHROMIUM_BUILDS
        and entry.get("installByDefault", True)
        and entry.get("revision")
    ]
    return names or None


# The only things the agent can install. Keyed by the name the model
# passes; every command is spelled out here and nowhere else. The pip
# requirement is pinned to the major line web.py was written against, and
# ``sys.executable`` targets the interpreter running the backend, so the
# package lands where the screenshot tool will import it from.
ALLOWLIST: dict[str, Installable] = {
    "browser": Installable(
        description=(
            "Headless Chromium (via Playwright) for web.screenshot. On Linux "
            "the browser may also need system libraries the install does not add."
        ),
        size_hint="~150-300 MB download",
        steps=(
            (sys.executable, "-m", "pip", "install", "playwright>=1.45,<2.0"),
            (sys.executable, "-m", "playwright", "install", "chromium"),
        ),
        detect=browser_installed,
    ),
}


def _error(message: str, **extra: Any) -> dict[str, Any]:
    return {"ok": False, "error": message, **extra}


def _tail(text: str) -> str:
    text = text.strip()
    return text[-_LOG_TAIL_CHARS:] if len(text) > _LOG_TAIL_CHARS else text


def _step_label(argv: tuple[str, ...]) -> str:
    # The interpreter path says nothing useful to the model; "python -m ..."
    # is what a human would type.
    return " ".join(("python", *argv[1:]))


async def _run_step(argv: list[str], timeout_s: float) -> tuple[int, str]:
    """Run one allowlisted step: no shell, stdin closed, output merged."""
    env = {
        **os.environ,
        # pip must never block on a prompt or spend the budget phoning home.
        "PIP_NO_INPUT": "1",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
    }
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env=env,
    )
    try:
        output, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
    except asyncio.TimeoutError:
        proc.kill()
        with contextlib.suppress(Exception):
            await proc.wait()
        raise
    return proc.returncode or 0, output.decode("utf-8", errors="replace")


class SystemToolkit:
    """Executes the built-in ``system.*`` actions.

    ``runner`` replaces the subprocess layer and ``detector`` the
    installed-check so tests exercise the allowlist and the control flow
    without installing anything. ``report_source`` returns the owner's
    capability report (``InstallationService.report``); when wired,
    ``capabilities`` includes it so the agent can say what is switched
    off or blocked, and why, instead of guessing.
    """

    def __init__(
        self,
        *,
        runner: Optional[StepRunner] = None,
        detector: Optional[Callable[[str], bool]] = None,
        timeout_s: float = INSTALL_TIMEOUT_S,
        report_source: Optional[Callable[[], Awaitable[list["CapabilityStatus"]]]] = None,
    ) -> None:
        self._runner = runner or _run_step
        self._detector = detector
        self._timeout_s = timeout_s
        self._report_source = report_source
        # Two approvals for the same capability arriving together must not
        # race two pip processes; the second waits and finds it installed.
        self._lock = asyncio.Lock()

    # -- Dispatch ------------------------------------------------------------

    async def execute(self, action: str, params: dict[str, Any]) -> dict[str, Any]:
        """Run one ``system.*`` action. Unknown actions fail closed."""
        handlers: dict[str, Callable[..., Awaitable[dict[str, Any]]]] = {
            "capabilities": self.capabilities,
            "install_capability": self.install_capability,
        }
        handler = handlers.get(action)
        if handler is None:
            return _error(f"Unknown system action '{action}'.")

        params = params or {}
        try:
            inspect.signature(handler).bind(**params)
        except TypeError as exc:
            return _error(f"Invalid arguments for system.{action}: {exc}")
        return await handler(**params)

    def _installed(self, name: str) -> bool:
        try:
            if self._detector is not None:
                return bool(self._detector(name))
            return bool(ALLOWLIST[name].detect())
        except Exception as exc:  # a broken probe reads as "missing", never raises
            logger.warning("capability_detection_failed", capability=name, error=str(exc))
            return False

    # -- Actions -------------------------------------------------------------

    async def capabilities(self) -> dict[str, Any]:
        """Every installable capability and whether it is installed right
        now, plus (when wired) the owner's permission switches."""
        result: dict[str, Any] = {
            "ok": True,
            "capabilities": [
                {
                    "name": name,
                    "installed": self._installed(name),
                    "description": capability.description,
                    "size_hint": capability.size_hint,
                }
                for name, capability in ALLOWLIST.items()
            ],
        }
        if self._report_source is not None:
            try:
                result["permissions"] = [s.to_dict() for s in await self._report_source()]
            except Exception as exc:
                # The install list is still useful on its own; say the
                # switches could not be read rather than fail the call.
                logger.warning("capability_report_failed", error_type=type(exc).__name__)
                result["permissions_error"] = "Could not read the permission switches."
        return result

    async def install_capability(self, name: str) -> dict[str, Any]:
        """Install one allowlisted capability.

        The caller (the executor) has already established that the user
        approved this call; nothing here re-checks that, and nothing here
        takes anything but the name from the model.
        """
        if not isinstance(name, str) or name not in ALLOWLIST:
            return _error("Unknown capability", allowed=sorted(ALLOWLIST))
        capability = ALLOWLIST[name]

        async with self._lock:
            if self._installed(name):
                return {"ok": True, "name": name, "already_installed": True}

            loop = asyncio.get_running_loop()
            deadline = loop.time() + self._timeout_s
            log = ""
            for argv in capability.steps:
                remaining = deadline - loop.time()
                try:
                    if remaining <= 0:
                        raise asyncio.TimeoutError
                    code, output = await self._runner(list(argv), remaining)
                except asyncio.TimeoutError:
                    return _error(
                        f"Installing '{name}' exceeded the "
                        f"{int(self._timeout_s // 60)}-minute limit while running: "
                        f"{_step_label(argv)}",
                        name=name,
                        installed_now=self._installed(name),
                        timed_out=True,
                        log_tail=_tail(log),
                    )
                except OSError as exc:
                    return _error(
                        f"Could not start '{_step_label(argv)}': {type(exc).__name__}",
                        name=name,
                        installed_now=False,
                        log_tail=_tail(log),
                    )
                log += output
                if code != 0:
                    return _error(
                        f"'{_step_label(argv)}' exited with status {code}.",
                        name=name,
                        installed_now=self._installed(name),
                        log_tail=_tail(log),
                    )

            installed = self._installed(name)
            result: dict[str, Any] = {
                "ok": True,
                "name": name,
                "installed_now": installed,
                "log_tail": _tail(log),
            }
            if not installed:
                # Every step succeeded but the probe still says missing:
                # most likely the probe is stricter than Playwright on this
                # platform. Say so rather than let the model loop on it.
                result["note"] = (
                    "The install steps completed but the capability was not "
                    "detected afterwards; try the tool that needed it anyway."
                )
            return result

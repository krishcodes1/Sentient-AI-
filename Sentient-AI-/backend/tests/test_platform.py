"""services/platform: OS selection, private profile dirs, window raising
and port diagnostics. Nothing here runs a real OS probe: every platform
takes an injected runner (an argv recorder) or user32 shim, and
CRAWLER_PLATFORM picks the implementation whatever OS runs the suite."""

from __future__ import annotations

import base64
import stat
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Optional

import pytest

from services import platform as platform_pkg
from services.platform import OVERRIDE_ENV, current, detect_name
from services.platform.base import (
    SecretStoreUnavailable,
    make_private_dir,
    parse_lsof,
    profile_path,
    read_or_create_id,
    run_argv,
    secret_name,
)
from services.platform.container import ContainerPlatform
from services.platform.linux import LinuxPlatform
from services.platform.mac import MacPlatform
from services.platform.windows import WindowsPlatform, parse_netstat, parse_tasklist

USER = "0f8fad5b-d9cb-469f-a165-70867728950e"
POSIX_ONLY = pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX mode bits")


class Recorder:
    """A Runner: records every argv (and what was fed to its stdin, one entry
    per call, None when nothing was) and replays canned (code, output) pairs."""

    def __init__(self, *results: tuple[int, str]) -> None:
        self.calls: list[list[str]] = []
        self.inputs: list[Optional[str]] = []
        self._results = list(results)

    def __call__(
        self, argv: list[str], timeout_s: float, stdin: Optional[str] = None
    ) -> tuple[int, str]:
        assert 0 < timeout_s <= 10
        self.calls.append(list(argv))
        self.inputs.append(stdin)
        return self._results.pop(0) if self._results else (0, "")


# -- base helpers ----------------------------------------------------------


def test_run_argv_returns_code_and_merged_output():
    code, out = run_argv(
        [sys.executable, "-c", "import sys; print('out'); print('err', file=sys.stderr); sys.exit(3)"],
        10.0,
    )
    assert code == 3
    assert sorted(out.split()) == ["err", "out"]


def test_run_argv_never_opens_a_console_window(monkeypatch):
    # On Windows a GUI-launched backend would flash a console for every
    # icacls/netstat probe; CREATE_NO_WINDOW (0 elsewhere) suppresses it.
    seen: dict = {}

    def fake_run(argv, **kwargs):
        seen.update(kwargs)
        raise OSError("not really running")

    monkeypatch.setattr("services.platform.base.subprocess.run", fake_run)
    assert run_argv(["/bin/true"], 1.0) == (-1, "")
    assert seen["creationflags"] == getattr(subprocess, "CREATE_NO_WINDOW", 0)
    assert seen["stdin"] is subprocess.DEVNULL and "shell" not in seen


def test_run_argv_feeds_stdin_only_when_given():
    read_back = [sys.executable, "-c", "import sys; print(repr(sys.stdin.read()))"]
    code, out = run_argv(read_back, 10.0, stdin="line one\nline two\n")
    assert (code, out.strip()) == (0, repr("line one\nline two\n"))
    # Without stdin the child reads an empty, closed stream (never the
    # backend's own stdin).
    code, out = run_argv(read_back, 10.0)
    assert (code, out.strip()) == (0, repr(""))


def test_run_argv_never_raises():
    assert run_argv(["/nonexistent/binary"], 1.0) == (-1, "")
    assert run_argv([sys.executable, "-c", "import time; time.sleep(5)"], 0.2) == (-1, "")


@pytest.mark.parametrize("bad", ["", "../etc", "a/b", "id with space", "x" * 65, "abc\n"])
def test_profile_path_refuses_anything_but_an_id(tmp_path, bad):
    with pytest.raises(ValueError):
        profile_path(tmp_path, bad)


def test_profile_path_is_under_browser_profiles(tmp_path):
    assert profile_path(tmp_path, USER) == tmp_path / "browser-profiles" / USER


@POSIX_ONLY
def test_make_private_dir_creates_0700_and_tightens_loose_dirs(tmp_path):
    fresh = make_private_dir(tmp_path / "a" / "b")
    assert fresh.is_dir() and stat.S_IMODE(fresh.stat().st_mode) == 0o700
    loose = tmp_path / "loose"
    loose.mkdir()
    loose.chmod(0o755)
    make_private_dir(loose)
    assert stat.S_IMODE(loose.stat().st_mode) == 0o700


@POSIX_ONLY
def test_make_private_dir_refuses_a_symlinked_profile(tmp_path):
    # chmod follows symlinks: a planted link must not redirect (or loosen)
    # where live cookies are written.
    target = tmp_path / "elsewhere"
    target.mkdir()
    target.chmod(0o755)
    link = tmp_path / "profile"
    link.symlink_to(target)
    with pytest.raises(OSError, match="symlink"):
        make_private_dir(link)
    assert stat.S_IMODE(target.stat().st_mode) == 0o755


def test_parse_lsof_takes_the_first_pid_command_pair():
    assert parse_lsof("p4242\ncGoogle Chrome\np4300\ncGoogle Chrome Helper\n") == "4242 Google Chrome"
    assert parse_lsof("") is None
    assert parse_lsof("cOrphan\n") is None


# -- Mac -------------------------------------------------------------------


def mac(tmp_path: Path, *results: tuple[int, str], chrome: bool = False) -> tuple[MacPlatform, Recorder]:
    rec = Recorder(*results)
    app = tmp_path / "Google Chrome.app"
    if chrome:
        app.mkdir()
    return MacPlatform(runner=rec, home=tmp_path, chrome_app=app), rec


def test_mac_data_dir_is_application_support(tmp_path):
    plat, _ = mac(tmp_path)
    assert plat.data_dir() == tmp_path / "Library" / "Application Support" / "Crawler AI"


@POSIX_ONLY
def test_mac_profile_dir_is_created_0700_under_data_dir(tmp_path):
    plat, rec = mac(tmp_path)
    profile = plat.profile_dir(USER)
    assert profile == plat.data_dir() / "browser-profiles" / USER
    assert profile.is_dir() and stat.S_IMODE(profile.stat().st_mode) == 0o700
    assert rec.calls == []  # chmod, not a subprocess


def test_mac_channel_is_chrome_only_when_the_app_exists(tmp_path):
    assert mac(tmp_path)[0].browser_channel() is None
    assert mac(tmp_path, chrome=True)[0].browser_channel() == "chrome"


# -- Windows ---------------------------------------------------------------


def windows(
    tmp_path: Path, *results: tuple[int, str], user32=None, **env_extra: str
) -> tuple[WindowsPlatform, Recorder]:
    env = {"LOCALAPPDATA": str(tmp_path / "Local"), "SYSTEMROOT": r"C:\Windows", "USERNAME": "krish"}
    env.update(env_extra)
    rec = Recorder(*results)
    return WindowsPlatform(runner=rec, env=env, user32=user32), rec


def test_windows_data_dir_is_localappdata(tmp_path):
    plat, _ = windows(tmp_path)
    assert plat.data_dir() == tmp_path / "Local" / "Crawler AI"


def test_windows_profile_dir_restricts_the_acl_to_the_current_user(tmp_path):
    ok = (0, "Successfully processed 1 files; Failed processing 0 files")
    plat, rec = windows(tmp_path, ok, ok)
    profile = plat.profile_dir(USER)
    assert profile == tmp_path / "Local" / "Crawler AI" / "browser-profiles" / USER
    assert profile.is_dir()
    # /reset drops explicit ACEs a pre-existing dir may carry (the Windows
    # twin of chmod-ing a loose dir back to 0700); the second call removes
    # the inherited ones and grants only the signed-in account.
    assert rec.calls == [
        [r"C:\Windows\System32\icacls.exe", str(profile), "/reset"],
        [r"C:\Windows\System32\icacls.exe", str(profile), "/inheritance:r", "/grant:r", "krish:(OI)(CI)F"],
    ]


def test_windows_profile_dir_uses_the_domain_account_when_domain_joined(tmp_path):
    plat, rec = windows(tmp_path, (0, "ok"), (0, "ok"), USERDOMAIN="CORP", COMPUTERNAME="KRISH-PC")
    plat.profile_dir(USER)
    assert rec.calls[-1][-1] == "CORP\\krish:(OI)(CI)F"
    plat, rec = windows(tmp_path, (0, "ok"), (0, "ok"), USERDOMAIN="KRISH-PC", COMPUTERNAME="KRISH-PC")
    plat.profile_dir(USER)
    assert rec.calls[-1][-1] == "krish:(OI)(CI)F"  # a workgroup machine: USERDOMAIN is the host


def test_windows_profile_dir_fails_closed_when_icacls_fails(tmp_path):
    plat, rec = windows(tmp_path, (5, "Access is denied."))
    with pytest.raises(OSError, match="icacls"):
        plat.profile_dir(USER)
    assert len(rec.calls) == 1  # a failed reset never goes on to "restrict"
    plat, _ = windows(tmp_path, (0, "ok"), (5, "Access is denied."))
    with pytest.raises(OSError, match="icacls"):
        plat.profile_dir(USER)


def test_windows_profile_dir_needs_a_username(tmp_path):
    plat, rec = windows(tmp_path, USERNAME="")
    with pytest.raises(OSError, match="USERNAME"):
        plat.profile_dir(USER)
    assert rec.calls == []


def test_windows_channel_prefers_chrome_and_falls_back_to_edge(tmp_path):
    plat, _ = windows(tmp_path, PROGRAMFILES=str(tmp_path / "PF"))
    assert plat.browser_channel() == "msedge"
    exe = tmp_path / "PF" / "Google" / "Chrome" / "Application" / "chrome.exe"
    exe.parent.mkdir(parents=True)
    exe.write_bytes(b"")
    assert plat.browser_channel() == "chrome"


# -- Linux and container ---------------------------------------------------


def test_linux_data_dir_honours_xdg_then_falls_back(tmp_path):
    xdg = LinuxPlatform(runner=Recorder(), home=tmp_path, env={"XDG_DATA_HOME": str(tmp_path / "xdg")})
    assert xdg.data_dir() == tmp_path / "xdg" / "Crawler AI"
    plain = LinuxPlatform(runner=Recorder(), home=tmp_path, env={})
    assert plain.data_dir() == tmp_path / ".local" / "share" / "Crawler AI"


def test_linux_channel_is_chrome_only_when_installed(tmp_path):
    plat = LinuxPlatform(runner=Recorder(), home=tmp_path, env={}, chrome_bin=tmp_path / "chrome")
    assert plat.browser_channel() is None
    (tmp_path / "chrome").write_bytes(b"")
    assert plat.browser_channel() == "chrome"


@POSIX_ONLY
def test_linux_profile_dir_is_0700(tmp_path):
    profile = LinuxPlatform(runner=Recorder(), home=tmp_path, env={}).profile_dir(USER)
    assert profile == tmp_path / ".local" / "share" / "Crawler AI" / "browser-profiles" / USER
    assert stat.S_IMODE(profile.stat().st_mode) == 0o700


def test_container_uses_bundled_chromium_and_scratch_data(tmp_path, monkeypatch):
    monkeypatch.setattr("services.platform.container.tempfile.gettempdir", lambda: str(tmp_path))
    plat = ContainerPlatform(runner=Recorder())
    assert plat.name == "container"
    assert plat.browser_channel() is None
    assert plat.data_dir() == tmp_path / "crawler-ai"


# -- bring_to_front --------------------------------------------------------


def test_mac_bring_to_front_by_pid_uses_system_events(tmp_path):
    plat, rec = mac(tmp_path, (0, ""))
    assert plat.bring_to_front(pid=4242) is True
    assert rec.calls == [[
        "/usr/bin/osascript",
        "-e",
        'tell application "System Events" to set frontmost of (first process whose unix id is 4242) to true',
    ]]


def test_mac_bring_to_front_without_pid_raises_the_running_browser(tmp_path):
    # System Events on a *running* process, not `tell application … to
    # activate`, which would launch the owner's own Chrome if Crawler's
    # window were gone.
    plat, rec = mac(tmp_path, (0, ""), chrome=True)
    assert plat.bring_to_front(title="Canvas") is True
    assert rec.calls == [[
        "/usr/bin/osascript",
        "-e",
        'tell application "System Events" to set frontmost of (first process whose name is "Google Chrome") to true',
    ]]
    # Playwright 1.63's bundled browser is "Google Chrome for Testing.app".
    plat, rec = mac(tmp_path / "nochrome", (0, ""))
    plat.bring_to_front()
    assert '(first process whose name is "Google Chrome for Testing")' in rec.calls[0][2]


def test_mac_bring_to_front_reports_osascript_failure(tmp_path):
    plat, _ = mac(tmp_path, (1, "execution error: Not authorized to send Apple events (-1743)"))
    assert plat.bring_to_front(pid=1) is False


class FakeUser32:
    def __init__(self, *, by_title=None, by_pid=None, foreground_ok=True) -> None:
        self.by_title = by_title or {}
        self.by_pid = by_pid or {}
        self.foreground_ok = foreground_ok
        self.raised: list[int] = []
        self.flashed: list[int] = []

    def find_window(self, title: str) -> int:
        return self.by_title.get(title, 0)

    def window_for_pid(self, pid: int) -> int:
        return self.by_pid.get(pid, 0)

    def set_foreground(self, hwnd: int) -> bool:
        self.raised.append(hwnd)
        return self.foreground_ok

    def flash(self, hwnd: int) -> None:
        self.flashed.append(hwnd)


def test_windows_bring_to_front_tries_title_then_pid(tmp_path):
    u = FakeUser32(by_title={"Canvas - Google Chrome": 0x10}, by_pid={77: 0x20})
    plat, _ = windows(tmp_path, user32=u)
    assert plat.bring_to_front(title="Canvas - Google Chrome", pid=77) is True
    assert plat.bring_to_front(title="gone", pid=77) is True
    assert u.raised == [0x10, 0x20]
    assert plat.bring_to_front(title="gone", pid=1) is False
    assert u.flashed == []


def test_windows_bring_to_front_flashes_when_foreground_is_refused(tmp_path):
    u = FakeUser32(by_pid={77: 0x20}, foreground_ok=False)
    plat, _ = windows(tmp_path, user32=u)
    assert plat.bring_to_front(pid=77) is False
    assert u.flashed == [0x20]


def test_windows_bring_to_front_is_false_off_windows_without_a_shim(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(
        "services.platform.windows._CtypesUser32",
        lambda: pytest.fail("the real user32 must never be built off Windows"),
    )
    plat, _ = windows(tmp_path)
    assert plat.bring_to_front(pid=1) is False


def test_windows_builds_the_real_user32_lazily_on_windows(tmp_path, monkeypatch):
    # The suite never touches the real desktop, on Windows CI included:
    # the ctypes shim is swapped for a fake at the one place it is built.
    built: list[FakeUser32] = []

    def factory() -> FakeUser32:
        built.append(FakeUser32(by_pid={77: 0x20}))
        return built[-1]

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr("services.platform.windows._CtypesUser32", factory)
    plat, _ = windows(tmp_path)
    assert plat.bring_to_front(pid=77) is True
    assert plat.bring_to_front(pid=77) is True
    assert len(built) == 1 and built[0].raised == [0x20, 0x20]


class _FakeDllFn:
    """A user32 export: records calls, accepts argtypes/restype like ctypes."""

    def __init__(self, impl) -> None:
        self.impl = impl
        self.calls: list[tuple] = []

    def __call__(self, *args):
        self.calls.append(args)
        return self.impl(*args)


def test_ctypes_user32_shim_wiring_against_a_fake_dll(monkeypatch):
    # The real shim, minus the real DLL: proves the EnumWindows callback,
    # pid matching, visibility filter and restore-before-foreground logic
    # on any OS without touching a desktop.
    import ctypes

    from services.platform.windows import _CtypesUser32

    windows_by_pid = {0x10: 5, 0x20: 77, 0x30: 77}  # hwnd -> owning pid
    visible = {0x10, 0x30}
    iconic = {0x30}

    def enum_windows(callback, _lparam):
        for hwnd in windows_by_pid:
            if not callback(hwnd, 0):
                break
        return 1

    def thread_pid(hwnd, owner_ref):
        owner_ref._obj.value = windows_by_pid[hwnd]
        return 1

    dll = type("FakeUser32Dll", (), {})()
    for name, impl in {
        "FindWindowW": lambda _cls, title: 0x10 if title == "Canvas" else None,
        "EnumWindows": enum_windows,
        "GetWindowThreadProcessId": thread_pid,
        "IsWindowVisible": lambda hwnd: hwnd in visible,
        "IsIconic": lambda hwnd: hwnd in iconic,
        "ShowWindow": lambda hwnd, cmd: 1,
        "SetForegroundWindow": lambda hwnd: 1,
        "FlashWindow": lambda hwnd, invert: 1,
    }.items():
        setattr(dll, name, _FakeDllFn(impl))
    monkeypatch.setattr(ctypes, "WinDLL", lambda name, use_last_error=False: dll, raising=False)
    monkeypatch.setattr(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE, raising=False)

    shim = _CtypesUser32()
    assert shim.find_window("Canvas") == 0x10
    assert shim.find_window("gone") == 0
    assert shim.window_for_pid(77) == 0x30  # 0x20 is pid 77 but hidden
    assert shim.window_for_pid(999) == 0
    assert shim.set_foreground(0x30) is True
    assert dll.ShowWindow.calls == [(0x30, 9)]  # SW_RESTORE, minimised only
    assert shim.set_foreground(0x10) is True
    assert len(dll.ShowWindow.calls) == 1
    shim.flash(0x10)
    assert dll.FlashWindow.calls == [(0x10, True)]


def test_linux_and_container_cannot_raise_a_window(tmp_path):
    assert LinuxPlatform(runner=Recorder(), home=tmp_path, env={}).bring_to_front(pid=1) is False
    assert ContainerPlatform(runner=Recorder()).bring_to_front(title="x") is False


# -- port_owner ------------------------------------------------------------

NETSTAT_OUT = """
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1180
  TCP    0.0.0.0:9222           0.0.0.0:0              LISTENING       4242
  TCP    [::]:9222              [::]:0                 LISTENING       4242
  TCP    127.0.0.1:49222        127.0.0.1:9222         ESTABLISHED     7000
  UDP    0.0.0.0:5353           *:*                                    2020
"""
TASKLIST_OUT = '"chrome.exe","4242","Console","1","187,532 K"\r\n'
TASKLIST_NONE = "INFO: No tasks are running which match the specified criteria.\r\n"


def test_mac_port_owner_parses_lsof_fields(tmp_path):
    plat, rec = mac(tmp_path, (0, "p4242\ncGoogle Chrome\n"))
    assert plat.port_owner(9222) == "4242 Google Chrome"
    assert rec.calls == [["/usr/sbin/lsof", "-nP", "-iTCP:9222", "-sTCP:LISTEN", "-Fpc"]]


def test_mac_port_owner_is_none_when_nothing_listens_or_lsof_is_missing(tmp_path):
    assert mac(tmp_path, (1, ""))[0].port_owner(9222) is None  # lsof exits 1 on no match
    assert mac(tmp_path, (-1, ""))[0].port_owner(9222) is None  # runner: binary missing


def test_linux_port_owner_uses_usr_bin_lsof(tmp_path):
    rec = Recorder((0, "p7\ncchrome\n"))
    assert LinuxPlatform(runner=rec, home=tmp_path, env={}).port_owner(80) == "7 chrome"
    assert rec.calls[0][0] == "/usr/bin/lsof"


def test_parse_netstat_finds_only_listening_tcp_rows():
    assert parse_netstat(NETSTAT_OUT, 9222) == 4242
    assert parse_netstat(NETSTAT_OUT, 49222) is None  # ESTABLISHED, not a listener
    assert parse_netstat(NETSTAT_OUT, 5353) is None  # UDP
    assert parse_netstat("", 9222) is None


def test_parse_netstat_does_not_depend_on_the_localised_state_word():
    # netstat translates the State column ("ABHÖREN", "ÉCOUTE", …); a
    # listener is the row whose foreign address has port 0.
    german = (
        "  Proto  Lokale Adresse         Remoteadresse          Status           PID\n"
        "  TCP    0.0.0.0:9222           0.0.0.0:0              ABH\ufffdREN          4242\n"
        "  TCP    127.0.0.1:9222         127.0.0.1:50000        HERGESTELLT      7000\n"
        "  TCP    [::]:9223              [::]:0                 ABH\ufffdREN          4343\n"
    )
    assert parse_netstat(german, 9222) == 4242
    assert parse_netstat(german, 9223) == 4343
    assert parse_netstat(german, 50000) is None


def test_parse_tasklist_reads_the_csv_row_for_the_pid():
    assert parse_tasklist(TASKLIST_OUT, 4242) == "chrome.exe"
    assert parse_tasklist(TASKLIST_OUT, 1) is None
    assert parse_tasklist(TASKLIST_NONE, 4242) is None


def test_windows_port_owner_chains_netstat_then_tasklist(tmp_path):
    plat, rec = windows(tmp_path, (0, NETSTAT_OUT), (0, TASKLIST_OUT))
    assert plat.port_owner(9222) == "4242 chrome.exe"
    assert rec.calls == [
        [r"C:\Windows\System32\netstat.exe", "-ano", "-p", "tcp"],
        [r"C:\Windows\System32\tasklist.exe", "/FI", "PID eq 4242", "/FO", "CSV", "/NH"],
    ]


def test_windows_port_owner_skips_tasklist_without_a_listener(tmp_path):
    plat, rec = windows(tmp_path, (0, NETSTAT_OUT))
    assert plat.port_owner(1) is None
    assert len(rec.calls) == 1


def test_windows_port_owner_falls_back_to_the_pid_alone(tmp_path):
    plat, _ = windows(tmp_path, (0, NETSTAT_OUT), (0, TASKLIST_NONE))
    assert plat.port_owner(9222) == "4242"


# -- current() / detect_name() ---------------------------------------------


@pytest.fixture(autouse=True)
def _fresh_selection():
    current.cache_clear()
    yield
    current.cache_clear()


@pytest.mark.parametrize(
    "override, cls",
    [
        ("mac", MacPlatform),
        ("windows", WindowsPlatform),
        ("linux", LinuxPlatform),
        ("container", ContainerPlatform),
    ],
)
def test_override_selects_each_platform_on_any_os(monkeypatch, override, cls):
    monkeypatch.setenv(OVERRIDE_ENV, override)
    picked = current()
    assert isinstance(picked, cls) and picked.name == override


def test_override_is_normalised_and_the_choice_is_cached(monkeypatch):
    monkeypatch.setenv(OVERRIDE_ENV, " Mac ")
    first = current()
    assert first.name == "mac"
    monkeypatch.setenv(OVERRIDE_ENV, "windows")
    assert current() is first  # cached until cache_clear()
    current.cache_clear()
    assert current().name == "windows"


def test_unknown_override_is_an_error_not_a_fallback(monkeypatch):
    monkeypatch.setenv(OVERRIDE_ENV, "amiga")
    with pytest.raises(ValueError, match=OVERRIDE_ENV):
        current()


def test_container_marker_wins_over_the_host_os(monkeypatch):
    monkeypatch.delenv(OVERRIDE_ENV, raising=False)
    monkeypatch.setenv("CRAWLER_CONTAINER", "1")  # what docker-compose sets
    assert detect_name() == "container"


@pytest.mark.parametrize("host, expected", [("darwin", "mac"), ("win32", "windows"), ("linux", "linux")])
def test_host_os_maps_to_a_platform(monkeypatch, host, expected):
    monkeypatch.delenv(OVERRIDE_ENV, raising=False)
    monkeypatch.setattr(platform_pkg, "in_container", lambda: False)
    monkeypatch.setattr(sys, "platform", host)
    assert detect_name() == expected


# -- secrets and vault_id (purchases spec §4) ------------------------------
#
# The vault key is the one thing the OS store holds. Mac goes through
# `/usr/bin/security -i` with the command on stdin (argv and stdin recorded,
# never run: the owner's Keychain is never touched), Windows through a
# Crypt32 shim (a fake that reverses bytes), Linux and the container have
# no store.

VAULT_UUID = "0f8fad5b-d9cb-469f-a165-70867728950e"
SERVICE = "Crawler AI vault"
ACCOUNT = f"{VAULT_UUID}-vault-key"
SECURITY_I = ["/usr/bin/security", "-i"]
KEY_B64 = base64.b64encode(b"k" * 32).decode()


def test_read_or_create_id_mints_a_uuid_once(tmp_path):
    path = tmp_path / "data" / "vault-id"
    first = read_or_create_id(path)
    assert str(uuid.UUID(first)) == first
    assert path.read_text().strip() == first
    assert read_or_create_id(path) == first


@POSIX_ONLY
def test_read_or_create_id_file_is_0600(tmp_path):
    path = tmp_path / "vault-id"
    read_or_create_id(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_read_or_create_id_never_overwrites_a_corrupt_file(tmp_path):
    # Replacing the id would change the Keychain account the key lives
    # under and orphan it: refuse instead.
    path = tmp_path / "vault-id"
    path.write_text("not a uuid\n")
    with pytest.raises(OSError, match="uuid"):
        read_or_create_id(path)
    assert path.read_text() == "not a uuid\n"


@POSIX_ONLY
def test_read_or_create_id_refuses_a_symlink(tmp_path):
    target = tmp_path / "elsewhere"
    target.write_text(VAULT_UUID)
    link = tmp_path / "vault-id"
    link.symlink_to(target)
    with pytest.raises(OSError, match="symlink"):
        read_or_create_id(link)


@pytest.mark.parametrize("bad", ["", "../key", "a/b", "vault key", "x" * 65])
def test_secret_name_refuses_anything_but_an_identifier(bad):
    with pytest.raises(ValueError):
        secret_name(bad)
    assert secret_name("vault-key") == "vault-key"


def test_mac_vault_id_lives_in_application_support(tmp_path):
    plat, rec = mac(tmp_path)
    vid = plat.vault_id()
    assert (plat.data_dir() / "vault-id").read_text().strip() == vid
    assert plat.vault_id() == vid and rec.calls == []


def _mac_with_id(tmp_path, *results):
    plat, rec = mac(tmp_path, *results)
    plat.data_dir().mkdir(parents=True)
    (plat.data_dir() / "vault-id").write_text(VAULT_UUID + "\n")
    return plat, rec


def test_mac_get_secret_reads_the_keychain_item_as_base64(tmp_path):
    plat, rec = _mac_with_id(tmp_path, (0, KEY_B64 + "\n"))
    assert plat.get_secret("vault-key") == b"k" * 32
    assert rec.calls == [SECURITY_I]
    assert rec.inputs == [f'"find-generic-password" "-s" "{SERVICE}" "-a" "{ACCOUNT}" "-w"\n']


def test_mac_get_secret_is_none_only_when_the_item_is_not_found(tmp_path):
    not_found = "security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain."
    plat, _ = _mac_with_id(tmp_path, (44, not_found))
    assert plat.get_secret("vault-key") is None
    # A locked keychain, a denied prompt or a missing binary must not read
    # as "no key yet": the caller would mint a new one over the old.
    for code in (1, 36, 51, 128, -1):
        plat, _ = _mac_with_id(tmp_path / f"c{code}", (code, "User interaction is not allowed."))
        with pytest.raises(SecretStoreUnavailable, match="Keychain") as info:
            plat.get_secret("vault-key")
        # One plain sentence for the owner; the exit code is logged, not shown.
        assert str(info.value) == "Crawler could not open this Mac's Keychain. Unlock the Mac and try again."


def test_mac_get_secret_refuses_an_item_that_is_not_base64(tmp_path):
    plat, _ = _mac_with_id(tmp_path, (0, "not base64!\n"))
    with pytest.raises(SecretStoreUnavailable, match="format"):
        plat.get_secret("vault-key")


def test_mac_set_secret_adds_or_updates_the_item(tmp_path):
    plat, rec = _mac_with_id(tmp_path, (0, ""))
    plat.set_secret("vault-key", b"k" * 32)
    assert rec.calls == [SECURITY_I]
    assert rec.inputs == [
        f'"add-generic-password" "-U" "-s" "{SERVICE}" "-a" "{ACCOUNT}" "-w" "{KEY_B64}"\n'
    ]
    denied = "security: SecKeychainItemCreateFromContent: User interaction is not allowed."
    plat, _ = _mac_with_id(tmp_path / "fail", (1, denied))
    with pytest.raises(SecretStoreUnavailable, match="Keychain"):
        plat.set_secret("vault-key", b"k" * 32)


def test_mac_vault_key_is_never_an_argument(tmp_path):
    """The key travels on stdin only: an argument is readable in the
    process table (`ps`, exec auditing) for as long as `security` runs."""
    plat, rec = _mac_with_id(tmp_path, (0, ""), (0, KEY_B64 + "\n"))
    key = b"k" * 32
    plat.set_secret("vault-key", key)
    plat.get_secret("vault-key")
    for argv in rec.calls:
        assert argv == SECURITY_I
        assert KEY_B64 not in " ".join(argv) and key.hex() not in " ".join(argv)
    # Every command ends in a newline: `security -i` runs nothing without one.
    assert all(line is not None and line.endswith("\n") and line.count("\n") == 1 for line in rec.inputs)


def test_mac_keychain_command_words_are_quoted_and_checked(tmp_path):
    from services.platform.mac import _quoted

    assert _quoted("Crawler AI vault") == '"Crawler AI vault"'
    assert _quoted(KEY_B64) == f'"{KEY_B64}"'
    for bad in ('a"b', "a\nb", "", "x\x00", "a'b"):
        with pytest.raises(ValueError):
            _quoted(bad)


@POSIX_ONLY
def test_mac_secrets_reach_a_real_security_binary_through_stdin(tmp_path, monkeypatch):
    """The real run_argv against a stand-in `security` (a script in tmp, so
    the owner's Keychain is never touched): it must be invoked as `-i`, get
    the whole command on stdin, and its `-w` output must read back as the
    key. This is the plumbing the recorded tests above take for granted."""
    from services.platform import mac as mac_module

    log = tmp_path / "commands.txt"
    fake = tmp_path / "security"
    fake.write_text(
        "#!/bin/sh\n"
        f"[ \"$1\" = -i ] || exit 99\n"
        f"line=$(cat)\n"
        f"printf '%s\\n' \"$line\" >> '{log}'\n"
        f"case \"$line\" in\n"
        f"  *find-generic-password*) printf '%s\\n' '{KEY_B64}' ;;\n"
        f"  *add-generic-password*) : ;;\n"
        f"  *) exit 2 ;;\n"
        f"esac\n"
    )
    fake.chmod(0o700)
    monkeypatch.setattr(mac_module, "_SECURITY", str(fake))
    plat = MacPlatform(runner=run_argv, home=tmp_path, chrome_app=tmp_path / "none.app")
    plat.data_dir().mkdir(parents=True)
    (plat.data_dir() / "vault-id").write_text(VAULT_UUID + "\n")
    plat.set_secret("vault-key", b"k" * 32)
    assert plat.get_secret("vault-key") == b"k" * 32
    lines = log.read_text().splitlines()
    assert lines == [
        f'"add-generic-password" "-U" "-s" "{SERVICE}" "-a" "{ACCOUNT}" "-w" "{KEY_B64}"',
        f'"find-generic-password" "-s" "{SERVICE}" "-a" "{ACCOUNT}" "-w"',
    ]


def test_mac_delete_secret_tolerates_a_missing_item(tmp_path):
    plat, rec = _mac_with_id(tmp_path, (0, ""), (44, "not found"), (1, "denied"))
    plat.delete_secret("vault-key")
    plat.delete_secret("vault-key")
    assert rec.calls == [SECURITY_I, SECURITY_I]
    assert rec.inputs[0] == f'"delete-generic-password" "-s" "{SERVICE}" "-a" "{ACCOUNT}"\n'
    with pytest.raises(SecretStoreUnavailable, match="Keychain"):
        plat.delete_secret("vault-key")


def test_mac_secret_name_is_validated_before_any_argv(tmp_path):
    plat, rec = _mac_with_id(tmp_path)
    with pytest.raises(ValueError):
        plat.get_secret("../../etc/passwd")
    assert rec.calls == []


class FakeCrypt32:
    """DPAPI stand-in: protect = tagged, reversed bytes, so the file on
    disk provably never holds the plaintext."""

    def __init__(self) -> None:
        self.protected = 0

    def protect(self, data: bytes) -> bytes:
        self.protected += 1
        return b"DPAPI:" + bytes(reversed(data))

    def unprotect(self, blob: bytes) -> bytes:
        assert blob.startswith(b"DPAPI:")
        return bytes(reversed(blob[6:]))


def test_windows_vault_id_lives_in_localappdata(tmp_path):
    plat, rec = windows(tmp_path)
    vid = plat.vault_id()
    assert (tmp_path / "Local" / "Crawler AI" / "vault-id").read_text().strip() == vid
    assert plat.vault_id() == vid and rec.calls == []


def test_windows_secret_is_dpapi_ciphertext_under_an_acl_restricted_dir(tmp_path):
    shim = FakeCrypt32()
    plat = WindowsPlatform(
        runner=(rec := Recorder()),
        env={"LOCALAPPDATA": str(tmp_path / "Local"), "SYSTEMROOT": r"C:\Windows", "USERNAME": "krish"},
        crypt32=shim,
    )
    assert plat.get_secret("vault-key") is None  # nothing stored, no icacls
    assert rec.calls == []

    plat.set_secret("vault-key", b"k" * 32)
    path = tmp_path / "Local" / "Crawler AI" / "secrets" / "vault-key.dpapi"
    assert path.read_bytes() == b"DPAPI:" + bytes(reversed(b"k" * 32))
    assert not path.with_name("vault-key.dpapi.tmp").exists()
    secrets_dir = str(path.parent)
    assert rec.calls == [
        [r"C:\Windows\System32\icacls.exe", secrets_dir, "/reset"],
        [r"C:\Windows\System32\icacls.exe", secrets_dir, "/inheritance:r", "/grant:r", "krish:(OI)(CI)F"],
    ]
    assert plat.get_secret("vault-key") == b"k" * 32

    plat.set_secret("vault-key", b"j" * 32)  # replace in place
    assert plat.get_secret("vault-key") == b"j" * 32 and shim.protected == 2

    plat.delete_secret("vault-key")
    assert not path.exists() and plat.get_secret("vault-key") is None
    plat.delete_secret("vault-key")  # already gone: not an error


def test_windows_set_secret_fails_closed_when_icacls_fails(tmp_path):
    plat = WindowsPlatform(
        runner=Recorder((5, "Access is denied.")),
        env={"LOCALAPPDATA": str(tmp_path / "Local"), "SYSTEMROOT": r"C:\Windows", "USERNAME": "krish"},
        crypt32=FakeCrypt32(),
    )
    with pytest.raises(OSError, match="icacls"):
        plat.set_secret("vault-key", b"k" * 32)
    assert not (tmp_path / "Local" / "Crawler AI" / "secrets" / "vault-key.dpapi").exists()


def test_windows_secrets_are_unavailable_off_windows_without_a_shim(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(
        "services.platform.windows._CtypesCrypt32",
        lambda: pytest.fail("the real crypt32 must never be built off Windows"),
    )
    plat, _ = windows(tmp_path)
    with pytest.raises(SecretStoreUnavailable, match="Windows"):
        plat.set_secret("vault-key", b"k" * 32)
    # A stored file with no way to unprotect it is unavailable, not absent.
    path = tmp_path / "Local" / "Crawler AI" / "secrets" / "vault-key.dpapi"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"DPAPI:x")
    with pytest.raises(SecretStoreUnavailable):
        plat.get_secret("vault-key")


def test_windows_builds_the_real_crypt32_lazily_on_windows(tmp_path, monkeypatch):
    built: list[FakeCrypt32] = []

    def factory() -> FakeCrypt32:
        built.append(FakeCrypt32())
        return built[-1]

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr("services.platform.windows._CtypesCrypt32", factory)
    plat, _ = windows(tmp_path)
    plat.set_secret("vault-key", b"k" * 32)
    assert plat.get_secret("vault-key") == b"k" * 32
    assert len(built) == 1


def test_ctypes_crypt32_shim_wiring_against_a_fake_dll(monkeypatch):
    # The real shim, minus the real DLL: proves the DATA_BLOB marshalling,
    # the UI_FORBIDDEN flag, the copy-out and the LocalFree on any OS.
    import ctypes

    from services.platform.windows import _CtypesCrypt32

    keep: list = []  # output buffers must outlive the call, as LocalAlloc's would

    def transform(blob_in_ref, descr, entropy, reserved, prompt, flags, blob_out_ref):
        assert flags == 0x01 and descr is None and entropy is None and prompt is None
        blob_in = blob_in_ref._obj
        data = ctypes.string_at(blob_in.pbData, blob_in.cbData)
        out = bytes(reversed(data))
        buffer = ctypes.create_string_buffer(out, len(out))
        keep.append(buffer)
        blob_out = blob_out_ref._obj
        blob_out.cbData = len(out)
        blob_out.pbData = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char))
        return 1

    dll = type("FakeCrypt32Dll", (), {})()
    dll.CryptProtectData = _FakeDllFn(transform)
    dll.CryptUnprotectData = _FakeDllFn(transform)
    dll.LocalFree = _FakeDllFn(lambda pointer: None)
    monkeypatch.setattr(ctypes, "WinDLL", lambda name, use_last_error=False: dll, raising=False)

    shim = _CtypesCrypt32()
    assert shim.protect(b"abc") == b"cba"
    assert shim.unprotect(b"cba") == b"abc"
    assert len(dll.LocalFree.calls) == 2

    dll.CryptUnprotectData = _FakeDllFn(lambda *args: 0)
    with pytest.raises(SecretStoreUnavailable, match="DPAPI"):
        shim.unprotect(b"cba")


def test_linux_has_no_secret_store_but_a_vault_id(tmp_path):
    plat = LinuxPlatform(runner=Recorder(), home=tmp_path, env={})
    with pytest.raises(SecretStoreUnavailable):
        plat.get_secret("vault-key")
    with pytest.raises(SecretStoreUnavailable):
        plat.set_secret("vault-key", b"k" * 32)
    with pytest.raises(SecretStoreUnavailable):
        plat.delete_secret("vault-key")
    assert uuid.UUID(plat.vault_id())


def test_container_has_neither_a_secret_store_nor_a_vault_id(tmp_path, monkeypatch):
    monkeypatch.setattr("services.platform.container.tempfile.gettempdir", lambda: str(tmp_path))
    plat = ContainerPlatform(runner=Recorder())
    with pytest.raises(SecretStoreUnavailable):
        plat.get_secret("vault-key")
    with pytest.raises(SecretStoreUnavailable):
        plat.vault_id()
    assert not (tmp_path / "crawler-ai" / "vault-id").exists()

"""Tests for installer/bootstrap.py: they prove that key validation and .env writing behave,
that the loopback API refuses missing tokens, foreign origins and foreign hosts, that
preflight and port diagnostics use the right tool per OS, that the compose build runner
reports state correctly, and that both launchers hand off to the bootstrap.

Why it exists: the installer runs unattended on machines nobody tests by hand, so these
guard against a secret leaking into logs or responses, an API reachable from another
origin, a launcher that no longer execs bootstrap.py, and line endings that bash or
cmd.exe cannot run.

Tests for the double-click bootstrap installer (installer/bootstrap.py).

Stdlib + pytest only. Everything runs against temp directories, fake
subprocesses and an in-process server on an ephemeral loopback port; nothing
here calls Docker or touches the real backend/.env.

Run from the project folder:  python3 -m pytest installer/tests -q
"""

from __future__ import annotations

import base64
import http.client
import json
import logging
import os
import re
import socket
import stat
import sys
import threading
import time
from pathlib import Path

import bootstrap  # importable via installer/tests/conftest.py
import pytest

INSTALLER_DIR = Path(__file__).resolve().parents[1]
PROJECT_DIR = INSTALLER_DIR.parent

EXAMPLE = (
    "# Crawler AI backend configuration\n"
    "#   python3 -c \"print('SECRET_KEY=' + secrets.token_urlsafe(48))\"\n"
    "SECRET_KEY=REPLACE_ME_run_the_command_above\n"
    "ENCRYPTION_KEY=REPLACE_ME_run_the_command_above\n"
    "\n"
    "#AUDIT_HMAC_KEY=\n"
    "DATABASE_URL=postgresql+asyncpg://sentientai:sentientai@localhost:5432/sentientai\n"
    "LLM_PROVIDER=anthropic\n"
    "ANTHROPIC_API_KEY=\n"
    'ALLOWED_HOSTS=["*"]\n'
)
GOOD_SECRET = "s3cr3t-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
GOOD_ENC = base64.urlsafe_b64encode(bytes(range(100, 132))).decode()
TOKEN = "test-token-" + "k" * 32
OK_ARGV = [sys.executable, "-c", "print('x');import sys;sys.exit(0)"]


# ── fixtures & helpers ───────────────────────────────────────────────────────


@pytest.fixture
def project(tmp_path: Path) -> bootstrap.InstallerPaths:
    for name in ("backend", "docker", "installer"):
        (tmp_path / name).mkdir()
    (tmp_path / "backend" / ".env.example").write_text(EXAMPLE)
    (tmp_path / "docker" / "docker-compose.yml").write_text("services: {}\n")
    (tmp_path / "installer" / "page.html").write_text(
        (INSTALLER_DIR / "page.html").read_text(encoding="utf-8"), encoding="utf-8"
    )
    return bootstrap.InstallerPaths(tmp_path)


def child_env(tmp_path: Path | None = None) -> dict:
    return {"PATH": os.environ.get("PATH", ""), "HOME": str(tmp_path or Path.home())}


def make_runner(paths: bootstrap.InstallerPaths, argv=None, **kwargs) -> bootstrap.BuildRunner:
    kwargs.setdefault("probe", lambda url: True)
    kwargs.setdefault("poll_interval", 0.01)
    kwargs.setdefault("frontend_url", None)
    return bootstrap.BuildRunner(paths.docker_dir, argv=argv or OK_ARGV, env=child_env(), **kwargs)


def wait_for(predicate, timeout: float = 15.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.02)
    raise AssertionError(f"condition not met within {timeout}s")


def ok(stdout: str = "", returncode: int = 0) -> bootstrap.CmdResult:
    return bootstrap.CmdResult(returncode == 0, returncode, stdout, "", None)


LSOF_POSTGRES = (
    "COMMAND   PID  USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n"
    "postgres  123 krish    7u  IPv6 0x1234      0t0  TCP [::1]:5432 (LISTEN)\n"
    "postgres  123 krish    8u  IPv4 0x5678      0t0  TCP 127.0.0.1:5432 (LISTEN)\n"
)


class FakeDocker:
    """Answers the preflight's docker/lsof calls; records every call."""

    def __init__(self, running: bool = True, compose: bool = True, ls_json: str = "[]") -> None:
        self.running = running
        self.compose = compose
        self.ls_json = ls_json
        self.calls: list = []

    def __call__(self, argv, timeout):
        self.calls.append((list(argv), timeout))
        args = list(argv[1:])
        tool = Path(argv[0]).name
        if tool == "lsof":
            return ok(LSOF_POSTGRES)
        if tool == "netstat":
            return ok(NETSTAT)
        if tool == "tasklist":
            return ok(TASKLIST[argv[2].split()[-1]])
        if args == ["--version"]:
            return ok("Docker version 28.4.0, build abc1234\n")
        if args[:1] == ["info"]:
            return ok("28.4.0\n") if self.running else ok("", returncode=1)
        if args[:2] == ["compose", "version"]:
            return ok("2.39.2\n") if self.compose else ok("", returncode=1)
        if args[:2] == ["compose", "ls"]:
            return ok(self.ls_json)
        raise AssertionError(f"unexpected command {argv}")


def fake_preflight(paths, docker: FakeDocker | None = None, which=None, os_name="mac") -> bootstrap.Preflight:
    return bootstrap.Preflight(
        paths,
        env=child_env(),
        run=docker or FakeDocker(),
        which=which or (lambda name: "/usr/local/bin/" + name),
        port_free=lambda port: port != 5432,
        disk_free=lambda: 42.5,
        os_name=os_name,
    )


class LiveServer:
    def __init__(self, app: bootstrap.InstallerApp) -> None:
        self.app = app
        self.server = bootstrap.make_server(app, ports=[0])
        self.port = app.port
        self.origin = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        )
        self.thread.start()

    def request(self, method, path, body=None, *, token=TOKEN, origin=True, referer=None,
                host=None, raw_body=None, content_type="application/json"):
        headers = {}
        if token:
            headers["X-Bootstrap-Token"] = token
        if origin is True:
            headers["Origin"] = self.origin
        elif origin:
            headers["Origin"] = origin
        if referer:
            headers["Referer"] = referer
        if host:
            headers["Host"] = host
        data = raw_body
        if body is not None:
            data = json.dumps(body).encode()
        if data is not None and content_type:
            headers["Content-Type"] = content_type
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        try:
            conn.request(method, path, body=data, headers=headers)
            resp = conn.getresponse()
            raw = resp.read()
        finally:
            conn.close()
        try:
            payload = json.loads(raw)
        except ValueError:
            payload = raw.decode("utf-8", "replace")
        return resp.status, payload, resp

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.app.runner.stop(timeout=5)


@pytest.fixture
def serve(project):
    servers = []

    def _serve(**kwargs) -> LiveServer:
        app = bootstrap.InstallerApp(
            project,
            TOKEN,
            preflight=kwargs.pop("preflight", None) or fake_preflight(project),
            runner=kwargs.pop("runner", None) or make_runner(project),
            open_url=kwargs.pop("open_url", lambda url: True),
            start_docker=kwargs.pop("start_docker", lambda: True),
        )
        server = LiveServer(app)
        servers.append(server)
        return server

    yield _serve
    for server in servers:
        server.close()


def read_env_values(path: Path) -> dict:
    values = {}
    for line in path.read_text().splitlines():
        match = re.match(r"^(?:export\s+)?(SECRET_KEY|ENCRYPTION_KEY)=(.*)$", line)
        if match:
            values[match.group(1)] = match.group(2)
    return values


# ── key validation ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "value",
    [GOOD_SECRET, bootstrap.generate_keys()[0], "x" * 20 + "ABCDEFGHIJKLM!%^&*()", (GOOD_SECRET * 13)[:512]],
)
def test_secret_key_accepts_strong_values(value):
    assert bootstrap.secret_key_problem(value) is None


@pytest.mark.parametrize(
    "value",
    [
        "",
        None,
        12345,
        "short",
        "AbCdEfGh" * 3 + "1234567",  # 31 chars
        "has space " + GOOD_SECRET,
        "tab\t" + GOOD_SECRET,
        GOOD_SECRET + "\n",
        "REPLACE_ME_run_the_command_above_xyz12",
        "a" * 40,  # too repetitive
        GOOD_SECRET + "$HOME",
        GOOD_SECRET + '"',
        GOOD_SECRET + "#comment",
        GOOD_SECRET + "é",
        "Q1w2E3r4" * 65,  # 520 chars
    ],
)
def test_secret_key_rejects_bad_values(value):
    problem = bootstrap.secret_key_problem(value)
    assert problem
    if isinstance(value, str) and len(value) > 8:
        assert value not in problem


def test_encryption_key_accepts_urlsafe_and_standard_base64():
    standard = base64.b64encode(b"\xfb\xff" * 16).decode()
    assert "+" in standard or "/" in standard
    for value in (GOOD_ENC, bootstrap.generate_keys()[1], standard):
        assert bootstrap.encryption_key_problem(value) is None


@pytest.mark.parametrize(
    "value",
    [
        "",
        None,
        base64.urlsafe_b64encode(os.urandom(16)).decode(),
        base64.urlsafe_b64encode(os.urandom(31)).decode(),
        base64.urlsafe_b64encode(os.urandom(33)).decode(),
        GOOD_ENC.rstrip("="),  # missing padding (the backend can't decode it)
        "!!!!" * 11,
        GOOD_ENC[:20] + " " + GOOD_ENC[20:],
        "REPLACE_ME_run_the_command_above",
    ],
)
def test_encryption_key_rejects_bad_values(value):
    assert bootstrap.encryption_key_problem(value)


def test_encryption_key_length_message_names_the_decoded_size():
    problem = bootstrap.encryption_key_problem(base64.urlsafe_b64encode(b"a" * 31).decode())
    assert "32 bytes" in problem and "31" in problem


def test_generated_keys_are_valid_and_fresh():
    first, second = bootstrap.generate_keys(), bootstrap.generate_keys()
    for secret, enc in (first, second):
        assert bootstrap.secret_key_problem(secret) is None
        assert bootstrap.encryption_key_problem(enc) is None
        assert len(base64.urlsafe_b64decode(enc)) == 32
    assert first != second


# ── .env writing ─────────────────────────────────────────────────────────────


def test_env_created_from_example_with_only_the_two_lines_replaced(project):
    writer = bootstrap.KeyWriter(project.env_file, project.env_example)
    result = writer.write("custom", secret_key=GOOD_SECRET, encryption_key=GOOD_ENC)

    assert result == {"ok": True, "wrote": True, "mode": "custom"}
    before = EXAMPLE.splitlines()
    after = project.env_file.read_text().splitlines()
    assert len(after) == len(before)
    changed = [(before[i], after[i]) for i in range(len(before)) if before[i] != after[i]]
    assert changed == [
        ("SECRET_KEY=REPLACE_ME_run_the_command_above", "SECRET_KEY=" + GOOD_SECRET),
        ("ENCRYPTION_KEY=REPLACE_ME_run_the_command_above", "ENCRYPTION_KEY=" + GOOD_ENC),
    ]
    assert project.env_file.read_text().endswith("\n")
    assert stat.S_IMODE(project.env_file.stat().st_mode) == 0o600
    assert bootstrap.env_key_status(project.env_file) == {"SECRET_KEY": True, "ENCRYPTION_KEY": True}


def test_generate_mode_writes_valid_keys_and_leaves_no_temp_files(project):
    result = bootstrap.KeyWriter(project.env_file, project.env_example).write("generate")

    assert result == {"ok": True, "wrote": True, "mode": "generate"}
    values = read_env_values(project.env_file)
    assert bootstrap.secret_key_problem(values["SECRET_KEY"]) is None
    assert bootstrap.encryption_key_problem(values["ENCRYPTION_KEY"]) is None
    assert sorted(p.name for p in project.backend_dir.iterdir()) == [".env", ".env.example"]


def test_existing_env_is_not_touched_without_overwrite(project):
    original = "SECRET_KEY=keep-me\nOTHER=1\n"
    project.env_file.write_text(original)
    writer = bootstrap.KeyWriter(project.env_file, project.env_example)

    assert writer.write("generate") == {"ok": False, "reason": "exists"}
    assert writer.write("generate", overwrite=False) == {"ok": False, "reason": "exists"}
    assert project.env_file.read_text() == original
    assert not list(project.backend_dir.glob(".env.bak-*"))


def test_overwrite_replaces_only_the_keys_and_keeps_a_private_backup(project):
    original = (
        "# my settings\n"
        "export SECRET_KEY=REPLACE_ME\n"
        "ANTHROPIC_API_KEY=sk-ant-keep-me\n"
        'ENCRYPTION_KEY="old"\n'
        "TELEGRAM_BOT_TOKEN=123:abc"  # no trailing newline
    )
    project.env_file.write_text(original)
    os.chmod(project.env_file, 0o644)
    writer = bootstrap.KeyWriter(project.env_file, project.env_example, clock=lambda: 1_700_000_000)

    result = writer.write("custom", secret_key=GOOD_SECRET, encryption_key=GOOD_ENC, overwrite=True)

    assert result["ok"] is True and result["wrote"] is True and result["mode"] == "custom"
    assert project.env_file.read_text() == (
        "# my settings\n"
        "export SECRET_KEY=" + GOOD_SECRET + "\n"
        "ANTHROPIC_API_KEY=sk-ant-keep-me\n"
        "ENCRYPTION_KEY=" + GOOD_ENC + "\n"
        "TELEGRAM_BOT_TOKEN=123:abc"
    )
    assert stat.S_IMODE(project.env_file.stat().st_mode) == 0o600
    backups = list(project.backend_dir.glob(".env.bak-*"))
    assert len(backups) == 1
    assert result["backup"] == "backend/" + backups[0].name
    assert backups[0].read_text() == original
    assert stat.S_IMODE(backups[0].stat().st_mode) == 0o600

    # A second overwrite in the same second gets its own backup file.
    writer.write("generate", overwrite=True)
    assert len(list(project.backend_dir.glob(".env.bak-*"))) == 2


def test_missing_key_lines_are_appended_and_crlf_is_preserved(project):
    project.env_file.write_bytes(b"SECRET_KEY=REPLACE_ME\r\nOTHER=1\r\n")
    writer = bootstrap.KeyWriter(project.env_file, project.env_example)

    writer.write("custom", secret_key=GOOD_SECRET, encryption_key=GOOD_ENC, overwrite=True)

    assert project.env_file.read_bytes() == (
        b"SECRET_KEY=" + GOOD_SECRET.encode() + b"\r\nOTHER=1\r\n"
        b"ENCRYPTION_KEY=" + GOOD_ENC.encode() + b"\n"
    )


def test_invalid_custom_keys_are_rejected_without_writing(project):
    writer = bootstrap.KeyWriter(project.env_file, project.env_example)
    result = writer.write("custom", secret_key="short-secret", encryption_key="bm90LWEta2V5")

    assert result["ok"] is False and result["reason"] == "invalid"
    assert set(result["errors"]) == {"secret_key", "encryption_key"}
    assert "short-secret" not in json.dumps(result) and "bm90LWEta2V5" not in json.dumps(result)
    assert not project.env_file.exists()


def test_missing_example_is_reported(project):
    project.env_example.unlink()
    result = bootstrap.KeyWriter(project.env_file, project.env_example).write("generate")
    assert result == {"ok": False, "reason": "no_example"}
    assert not project.env_file.exists()


def test_env_key_status_only_reports_booleans(project):
    assert bootstrap.env_key_status(project.env_file) == {"SECRET_KEY": False, "ENCRYPTION_KEY": False}
    project.env_file.write_text(EXAMPLE)
    assert bootstrap.env_key_status(project.env_file) == {"SECRET_KEY": False, "ENCRYPTION_KEY": False}
    project.env_file.write_text(
        f'SECRET_KEY="{GOOD_SECRET}"  # quoted\nENCRYPTION_KEY={GOOD_ENC} # inline comment\n'
    )
    assert bootstrap.env_key_status(project.env_file) == {"SECRET_KEY": True, "ENCRYPTION_KEY": True}


def test_key_values_never_reach_the_logs(project, caplog):
    caplog.set_level(logging.DEBUG, logger=bootstrap.LOGGER_NAME)
    writer = bootstrap.KeyWriter(project.env_file, project.env_example)

    responses = [
        writer.write("custom", secret_key=GOOD_SECRET, encryption_key=GOOD_ENC),
        writer.write("custom", secret_key=GOOD_SECRET, encryption_key=GOOD_ENC),  # exists
        writer.write("custom", secret_key=GOOD_SECRET[:12], encryption_key=GOOD_ENC[:12]),  # invalid
        writer.write("generate", overwrite=True),
    ]
    bootstrap.env_key_status(project.env_file)
    generated = read_env_values(project.env_file)

    assert "wrote backend/.env" in caplog.text  # logging did happen...
    secrets_seen = [GOOD_SECRET, GOOD_ENC, GOOD_SECRET[:12], GOOD_ENC[:12], *generated.values()]
    for value in secrets_seen:  # ...but never with a key in it
        assert value not in caplog.text
        assert value not in json.dumps(responses)


# ── HTTP: security ───────────────────────────────────────────────────────────


def test_page_is_served_with_a_nonce_csp(serve):
    server = serve()
    status, body, resp = server.request("GET", "/", token=None, origin=None)

    assert status == 200
    assert resp.getheader("Content-Type").startswith("text/html")
    csp = resp.getheader("Content-Security-Policy")
    nonce = re.search(r"'nonce-([^']+)'", csp).group(1)
    assert "default-src 'none'" in csp and "connect-src 'self'" in csp
    assert "__CSP_NONCE__" not in body
    assert body.count(f'nonce="{nonce}"') == 2
    assert resp.getheader("X-Frame-Options") == "DENY"
    assert resp.getheader("Cache-Control") == "no-store"


def test_api_requires_the_token(serve):
    server = serve()
    assert server.request("GET", "/api/check", token=None)[0] == 403
    assert server.request("GET", "/api/check", token="wrong-token")[0] == 403
    assert server.request("POST", "/api/keys", {"mode": "generate"}, token=None)[0] == 403
    assert not server.app.paths.env_file.exists()
    assert server.request("GET", "/api/check")[0] == 200


def test_api_rejects_a_foreign_origin(serve):
    server = serve()
    for origin in ("http://evil.example", "null", f"http://127.0.0.1:{server.port + 1}",
                   f"https://127.0.0.1:{server.port}"):
        assert server.request("GET", "/api/check", origin=origin)[0] == 403
    assert server.request("POST", "/api/build", {}, origin="http://evil.example")[0] == 403


def test_api_needs_origin_or_same_origin_referer(serve):
    server = serve()
    assert server.request("GET", "/api/check", origin=None)[0] == 403
    assert server.request("GET", "/api/check", origin=None, referer="http://evil.example/")[0] == 403
    status, _, _ = server.request("GET", "/api/check", origin=None, referer=server.origin + "/")
    assert status == 200


def test_foreign_host_header_is_rejected(serve):
    server = serve()
    host = f"evil.example:{server.port}"
    assert server.request("GET", "/api/check", host=host)[0] == 403
    assert server.request("GET", "/", host=host, token=None, origin=None)[0] == 403


def test_cors_preflight_and_other_files_are_refused(serve):
    server = serve()
    status, _, resp = server.request("OPTIONS", "/api/keys")
    assert status == 403 and resp.getheader("Access-Control-Allow-Origin") is None
    for path in ("/bootstrap.py", "/page.html", "/../backend/.env", "/installer/bootstrap.log"):
        assert server.request("GET", path, token=None, origin=None)[0] == 404
    assert server.request("GET", "/api/nope")[0] == 404
    assert server.request("GET", "/api/keys")[0] == 405


def test_request_bodies_are_validated(serve):
    server = serve()
    assert server.request("POST", "/api/keys", raw_body=b"[1, 2]")[0] == 400
    assert server.request("POST", "/api/keys", raw_body=b"{nope")[0] == 400
    assert server.request("POST", "/api/keys", raw_body=b"{}", content_type="text/plain")[0] == 415
    assert server.request("POST", "/api/keys", raw_body=b"{" + b" " * 20000 + b"}")[0] == 413
    assert server.request("POST", "/api/keys", {"mode": "sideways"})[0] == 400
    assert not server.app.paths.env_file.exists()


# ── HTTP: check ──────────────────────────────────────────────────────────────


def test_check_endpoint_shape(serve):
    server = serve()
    status, report, _ = server.request("GET", "/api/check")

    assert status == 200
    for key, kind in {
        "docker_installed": bool, "docker_running": bool, "compose_v2": bool, "ports": list,
        "disk_free_gb": float, "env_exists": bool, "env_keys_set": bool, "existing_stack": bool,
        "fixes": list, "ready": bool, "build_state": str,
    }.items():
        assert isinstance(report[key], kind), key
    assert report["docker_installed"] and report["docker_running"] and report["compose_v2"]
    assert report["ready"] is True and report["build_state"] == "idle"
    assert [p["port"] for p in report["ports"]] == [3000, 8000, 5432, 6379]
    blocked = [p for p in report["ports"] if not p["free"]]
    assert blocked == [{"port": 5432, "service": "database", "free": False,
                        "holder": "postgres (pid 123)", "docker": False, "ours": False}]
    port_fix = [f for f in report["fixes"] if f["id"] == "ports"]
    assert len(port_fix) == 1 and "postgres (pid 123)" in port_fix[0]["text"]
    assert report["disk_free_gb"] == 42.5


def test_preflight_runs_read_only_commands_with_timeouts(project):
    docker = FakeDocker()
    fake_preflight(project, docker).check()

    argvs = [call[0] for call in docker.calls]
    assert ["/usr/local/bin/docker", "--version"] in argvs
    assert ["/usr/local/bin/docker", "info", "--format", "{{.ServerVersion}}"] in argvs
    assert ["/usr/local/bin/docker", "compose", "version", "--short"] in argvs
    assert ["/usr/local/bin/docker", "compose", "ls", "--all", "--format", "json"] in argvs
    assert ["/usr/local/bin/lsof", "-nP", "-iTCP:5432", "-sTCP:LISTEN"] in argvs
    assert all(0 < timeout <= 10 for _, timeout in docker.calls)
    assert not any(verb in argv for argv in argvs for verb in ("up", "down", "build", "rm", "stop"))


@pytest.mark.parametrize(
    "os_name, label, must_mention",
    [
        ("mac", "Download Docker Desktop for Mac", "Apple chip"),
        ("windows", "Download Docker Desktop for Windows", "WSL 2"),
    ],
)
def test_preflight_without_docker_links_to_docker_desktop(project, os_name, label, must_mention):
    report = fake_preflight(project, which=lambda name: None, os_name=os_name).check()

    assert report["os"] == os_name
    assert report["docker_installed"] is False and report["ready"] is False
    fix = next(f for f in report["fixes"] if f["id"] == "docker_installed")
    assert fix["severity"] == "error" and must_mention in fix["text"]
    assert fix["link"] == {"href": bootstrap.DOCKER_DESKTOP_URL, "label": label}


@pytest.mark.parametrize("os_name, must_mention", [("mac", "menu bar"), ("windows", "Start menu")])
def test_preflight_with_docker_stopped(project, os_name, must_mention):
    docker = FakeDocker(running=False)
    report = fake_preflight(project, docker, os_name=os_name).check()

    assert report["docker_installed"] is True and report["docker_running"] is False
    assert report["ready"] is False
    fix = next(f for f in report["fixes"] if f["id"] == "docker_running")
    assert "wait until it says" in fix["text"] and must_mention in fix["text"]
    assert not any(argv[1:3] == ["compose", "ls"] for argv, _ in docker.calls)


def test_preflight_without_compose_v2(project):
    report = fake_preflight(project, FakeDocker(compose=False)).check()
    assert report["compose_v2"] is False and report["ready"] is False
    assert any(f["id"] == "compose_v2" for f in report["fixes"])


def test_preflight_reports_existing_keys_and_stack(project):
    bootstrap.KeyWriter(project.env_file, project.env_example).write("generate")
    ls_json = json.dumps([
        {"Name": "docker", "Status": "running(4)", "ConfigFiles": str(project.compose_file)},
    ])
    report = fake_preflight(project, FakeDocker(ls_json=ls_json)).check()

    assert report["env_exists"] is True and report["env_keys_set"] is True
    assert report["existing_stack"] is True and report["existing_stack_status"] == "running(4)"
    assert report["stack_conflict"] is None
    assert any(f["id"] == "env" and "skip to Build" in f["text"] for f in report["fixes"])


def test_port_fixes_point_at_containers_not_docker_desktop():
    docker_port = {"port": 3000, "service": "web app", "free": False,
                   "holder": "Docker Desktop (pid 9)", "docker": True, "ours": False}
    text = bootstrap._port_fix_text(docker_port, stack_conflict=True)
    assert "Docker container" in text and "other Crawler AI copy" in text
    assert "Quit" not in text
    mixed = dict(docker_port, holder="postgres (pid 1), Docker Desktop (pid 9)")
    assert "Quit them" in bootstrap._port_fix_text(mixed, stack_conflict=False)
    unknown = dict(docker_port, holder=None, docker=False)
    assert "another app" in bootstrap._port_fix_text(unknown, stack_conflict=False)


def test_find_stack_flags_a_same_named_project_from_another_folder(tmp_path):
    compose = tmp_path / "copy-a" / "docker" / "docker-compose.yml"
    other = "/Users/someone/other-copy/docker/docker-compose.yml"
    result = bootstrap.find_stack(
        json.dumps([{"Name": "crawler-ai", "Status": "running(4)", "ConfigFiles": other}]), compose
    )
    assert result["existing_stack"] is False
    assert result["stack_conflict"] == {
        "name": "crawler-ai", "status": "running(4)", "folder": "/Users/someone/other-copy",
    }
    assert bootstrap.find_stack("not json", compose)["existing_stack"] is False
    assert bootstrap.find_stack("", compose)["stack_conflict"] is None


def test_compose_commands_use_the_fixed_project_name(monkeypatch):
    monkeypatch.setattr(bootstrap.shutil, "which", lambda name, path=None: "/usr/local/bin/docker")
    up = bootstrap.compose_up_argv({"PATH": "/usr/local/bin"})
    assert up[:5] == ["/usr/local/bin/docker", "compose", "-p", "crawler-ai", "up"]
    assert bootstrap.COMPOSE_PROJECT == "crawler-ai"


def test_hand_started_stack_from_this_folder_is_a_warning(tmp_path):
    compose = tmp_path / "docker" / "docker-compose.yml"
    compose.parent.mkdir()
    compose.write_text("services: {}\n")
    result = bootstrap.find_stack(
        json.dumps([{"Name": "docker", "Status": "running(4)", "ConfigFiles": str(compose)}]), compose
    )
    assert result["existing_stack"] is True
    assert result["existing_stack_name"] == "docker"


def test_parse_lsof_names_the_process_and_spots_docker():
    assert bootstrap.parse_lsof(LSOF_POSTGRES) == {"holder": "postgres (pid 123)", "docker": False}
    docker_out = (
        "COMMAND     PID  USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n"
        "com.docke 4242 krish  150u  IPv6 0x1      0t0  TCP *:3000 (LISTEN)\n"
    )
    assert bootstrap.parse_lsof(docker_out) == {"holder": "Docker Desktop (pid 4242)", "docker": True}
    assert bootstrap.parse_lsof("COMMAND PID\n") is None


NETSTAT = (
    "\nActive Connections\n\n"
    "  Proto  Local Address          Foreign Address        State           PID\n"
    "  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1000\n"
    "  TCP    0.0.0.0:5432           0.0.0.0:0              LISTENING       4321\n"
    "  TCP    127.0.0.1:5432         127.0.0.1:50000        ESTABLISHED     4321\n"
    "  TCP    127.0.0.1:50000        127.0.0.1:5432         ESTABLISHED     7777\n"
    "  TCP    [::]:5432              [::]:0                 ABH\u00d6REN         4321\n"
    "  TCP    0.0.0.0:15432          0.0.0.0:0              LISTENING       9999\n"
    "  TCP    0.0.0.0:3000           0.0.0.0:0              LISTENING       5150\n"
    "  UDP    0.0.0.0:5432           *:*                                    8888\n"
)
TASKLIST = {
    "4321": '"postgres.exe","4321","Services","0","12,345 K"\r\n',
    "5150": '"com.docker.backend.exe","5150","Console","1","98,765 K"\r\n',
}


def test_parse_netstat_finds_listeners_in_any_language():
    assert bootstrap.parse_netstat(NETSTAT, 5432) == ["4321"]
    assert bootstrap.parse_netstat(NETSTAT, 3000) == ["5150"]
    assert bootstrap.parse_netstat(NETSTAT, 8000) == []
    assert bootstrap.parse_tasklist(TASKLIST["4321"]) == "postgres.exe"
    assert bootstrap.parse_tasklist("INFO: No tasks are running which match the specified criteria.\r\n") is None


def fake_port_tools(calls: list):
    """Pretend lsof (macOS/Linux) and netstat + tasklist (Windows) exist."""

    def run(argv, timeout):
        calls.append((list(argv), timeout))
        tool = Path(argv[0]).name
        if tool == "lsof":
            port = argv[2].split(":")[1]
            out = LSOF_POSTGRES if port == "5432" else (
                "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
                "com.docke 5150 me 150u IPv6 0x1 0t0 TCP *:3000 (LISTEN)\n"
            )
            return ok(out)
        if tool == "netstat":
            return ok(NETSTAT)
        if tool == "tasklist":
            return ok(TASKLIST[argv[2].split()[-1]])
        raise AssertionError(f"unexpected command {argv}")

    return run


@pytest.mark.parametrize(
    "os_name, port, expected",
    [
        ("mac", 5432, {"holder": "postgres (pid 123)", "docker": False}),
        ("mac", 3000, {"holder": "Docker Desktop (pid 5150)", "docker": True}),
        ("linux", 5432, {"holder": "postgres (pid 123)", "docker": False}),
        ("windows", 5432, {"holder": "postgres.exe (pid 4321)", "docker": False}),
        ("windows", 3000, {"holder": "Docker Desktop (pid 5150)", "docker": True}),
    ],
)
def test_port_holder_uses_the_right_tool_per_os(project, os_name, port, expected):
    calls: list = []
    preflight = bootstrap.Preflight(
        project, env=child_env(), run=fake_port_tools(calls), which=lambda name: "/bin/" + name,
        os_name=os_name,
    )
    assert preflight.port_holder(port) == expected
    tools = {Path(argv[0]).name for argv, _ in calls}
    assert tools == ({"netstat", "tasklist"} if os_name == "windows" else {"lsof"})
    assert all(0 < timeout <= 10 for _, timeout in calls)


@pytest.mark.parametrize("os_name", ["mac", "windows"])
def test_port_is_free_detects_a_listener(os_name):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    try:
        assert bootstrap.port_is_free(listener.getsockname()[1], os_name) is False
    finally:
        listener.close()
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    free_port = probe.getsockname()[1]
    probe.close()
    assert bootstrap.port_is_free(free_port, os_name) is True


@pytest.mark.parametrize("os_name, applied", [("mac", True), ("linux", True), ("windows", False)])
def test_chmod_private_per_os(tmp_path, os_name, applied):
    target = tmp_path / "secret.txt"
    target.write_text("x")
    os.chmod(target, 0o644)

    assert bootstrap._chmod_private(target, os_name) is applied
    assert stat.S_IMODE(target.stat().st_mode) == (0o600 if applied else 0o644)


@pytest.mark.parametrize("os_name", ["mac", "windows"])
def test_chmod_private_never_raises(monkeypatch, tmp_path, os_name):
    def refuse(*args, **kwargs):
        raise OSError("modes not supported here")

    monkeypatch.setattr(bootstrap.os, "chmod", refuse)
    monkeypatch.delattr(bootstrap.os, "fchmod", raising=False)  # as on Windows before 3.13
    assert bootstrap._chmod_private(tmp_path / "x", os_name) is False
    assert bootstrap._chmod_private(3, os_name) is False


def test_build_env_is_minimal_on_posix():
    env = bootstrap.build_env({
        "PATH": "/custom/bin", "HOME": "/Users/me", "DOCKER_HOST": "unix:///tmp/docker.sock",
        "SECRET_KEY": "leak", "ANTHROPIC_API_KEY": "sk-leak", "COMPOSE_FILE": "evil.yml",
        "PYTHONPATH": "/x",
    }, os_name="mac")
    assert set(env) == {"PATH", "HOME", "DOCKER_HOST", "COMPOSE_ANSI", "BUILDKIT_PROGRESS"}
    assert env["PATH"].split(":")[0] == "/custom/bin"
    assert "/usr/local/bin" in env["PATH"].split(":")


def test_build_env_is_minimal_on_windows():
    env = bootstrap.build_env({
        "Path": "C:\\Windows\\system32;C:\\Windows",
        "SystemRoot": "C:\\Windows",
        "USERPROFILE": "C:\\Users\\me",
        "ProgramFiles": "C:\\Program Files",
        "ProgramData": "C:\\ProgramData",
        "PATHEXT": ".COM;.EXE;.BAT",
        "DOCKER_HOST": "npipe:////./pipe/docker_engine",
        "SECRET_KEY": "leak",
        "OPENAI_API_KEY": "sk-leak",
        "COMPOSE_FILE": "evil.yml",
    }, os_name="windows")
    assert set(env) == {
        "PATH", "SystemRoot", "USERPROFILE", "ProgramFiles", "ProgramData", "PATHEXT",
        "DOCKER_HOST", "COMPOSE_ANSI", "BUILDKIT_PROGRESS",
    }
    parts = env["PATH"].split(";")
    assert parts[:2] == ["C:\\Windows\\system32", "C:\\Windows"]
    assert "C:\\Program Files\\Docker\\Docker\\resources\\bin" in parts
    assert "C:\\ProgramData\\DockerDesktop\\version-bin" in parts


@pytest.mark.parametrize(
    "platform, expected",
    [("darwin", "mac"), ("win32", "windows"), ("linux", "linux"), ("freebsd14", "linux")],
)
def test_current_os(platform, expected):
    assert bootstrap.current_os(platform) == expected


def test_launcher_and_child_process_options_per_os():
    assert bootstrap.launcher_name("mac") == "Install Crawler AI.command"
    assert bootstrap.launcher_name("windows") == "Install Crawler AI.bat"
    assert bootstrap.detached_child_kwargs("mac") == {"start_new_session": True}
    assert set(bootstrap.detached_child_kwargs("windows")) == {"creationflags"}
    assert bootstrap.default_start_docker("linux") is False
    if bootstrap.current_os() != "windows":
        assert bootstrap.default_start_docker("windows") is False  # no Docker Desktop.exe here


# ── keys over HTTP ───────────────────────────────────────────────────────────


def test_keys_endpoint_flow(serve):
    server = serve()
    status, body, _ = server.request("POST", "/api/keys", {"mode": "generate"})
    assert (status, body) == (200, {"ok": True, "wrote": True, "mode": "generate"})

    status, body, _ = server.request("POST", "/api/keys", {"mode": "generate"})
    assert (status, body) == (409, {"ok": False, "reason": "exists"})

    status, body, _ = server.request("POST", "/api/keys", {"mode": "generate", "overwrite": "yes"})
    assert status == 409  # only a real JSON true overwrites

    status, body, _ = server.request("POST", "/api/keys", {"mode": "generate", "overwrite": True})
    assert status == 200 and body["backup"].startswith("backend/.env.bak-")

    status, body, _ = server.request(
        "POST", "/api/keys", {"mode": "custom", "secret_key": "short", "encryption_key": "x", "overwrite": True}
    )
    assert status == 400 and set(body["errors"]) == {"secret_key", "encryption_key"}


def test_keys_endpoint_never_echoes_or_logs_values(serve, tmp_path):
    log_file = tmp_path / "bootstrap.log"
    handlers = bootstrap.configure_logging(log_file, verbose=True)
    try:
        server = serve()
        status, body, _ = server.request(
            "POST", "/api/keys", {"mode": "custom", "secret_key": GOOD_SECRET, "encryption_key": GOOD_ENC}
        )
        server.request("POST", "/api/keys", {"mode": "generate", "overwrite": True})
        generated = read_env_values(server.app.paths.env_file)
    finally:
        logger = logging.getLogger(bootstrap.LOGGER_NAME)
        for handler in handlers:
            logger.removeHandler(handler)
            handler.close()

    assert status == 200 and body == {"ok": True, "wrote": True, "mode": "custom"}
    text = log_file.read_text()
    assert "wrote backend/.env" in text
    for value in (GOOD_SECRET, GOOD_ENC, *generated.values(), TOKEN):
        assert value not in text
    assert stat.S_IMODE(log_file.stat().st_mode) == 0o600


# ── build ────────────────────────────────────────────────────────────────────


def test_build_runs_compose_then_reaches_healthy_and_refuses_a_second_start(serve):
    server = serve()
    bootstrap.KeyWriter(server.app.paths.env_file, server.app.paths.env_example).write("generate")

    status, body, _ = server.request("POST", "/api/build", {})
    assert status == 202 and body["ok"] is True

    def finished():
        status = server.request("GET", "/api/build/status?since=0")[1]
        return status if status["state"] in ("healthy", "failed") else None

    final = wait_for(finished)
    assert final["state"] == "healthy", final
    assert "x" in final["lines"]
    assert final["next"] == len(final["lines"])
    assert isinstance(final["elapsed_s"], int) and "error" not in final

    status, body, _ = server.request("POST", "/api/build", {})
    assert status == 409 and body["reason"] == "already_started" and body["state"] == "healthy"

    status, tail, _ = server.request("GET", "/api/build/status?since={}".format(final["next"]))
    assert tail["lines"] == [] and tail["next"] == final["next"]
    assert server.request("GET", "/api/build/status?since=banana")[0] == 200


def test_build_needs_keys_first(serve):
    server = serve()
    status, body, _ = server.request("POST", "/api/build", {})
    assert (status, body) == (400, {"ok": False, "reason": "keys_missing"})
    assert server.app.runner.state == "idle"


def test_second_build_while_running_is_409(serve, project):
    slow = [sys.executable, "-c", "import time;print('building', flush=True);time.sleep(1.5)"]
    server = serve(runner=make_runner(project, slow))
    bootstrap.KeyWriter(project.env_file, project.env_example).write("generate")

    assert server.request("POST", "/api/build", {})[0] == 202
    status, body, _ = server.request("POST", "/api/build", {})
    assert status == 409 and body["state"] in ("building", "starting")
    # Keys can't change under a running build either.
    assert server.request("POST", "/api/keys", {"mode": "generate", "overwrite": True})[0] == 409
    server.app.runner.wait(10)
    assert server.app.runner.state == "healthy"


def test_failing_compose_reports_failed_with_lines_and_a_hint(project):
    script = (
        "import sys;print('Step 1/3 ok');"
        "print('Error response from daemon: Ports are not available: port is already allocated', file=sys.stderr);"
        "sys.exit(3)"
    )
    failing = [sys.executable, "-c", script]
    runner = make_runner(project, failing)
    assert runner.start() is True
    runner.wait(10)

    status = runner.status(0)
    assert status["state"] == "failed"
    assert "exit code 3" in status["error"] and "port" in status["error"].lower()
    assert "Step 1/3 ok" in status["lines"]
    assert any("port is already allocated" in line for line in status["lines"])
    assert any(line.endswith("port is already allocated") for line in runner.tail(30))

    # A failed build may be retried.
    assert runner.start() is True
    runner.wait(10)
    assert any(line.startswith("----- retry #1") for line in runner.status(0)["lines"])


def test_health_timeout_fails_the_build(project):
    runner = make_runner(project, probe=lambda url: False, health_timeout=0.1)
    runner.start()
    runner.wait(10)
    status = runner.status(0)
    assert status["state"] == "failed" and "didn't answer" in status["error"]


def test_health_polling_uses_http_ok_by_default(project, monkeypatch):
    seen = []
    monkeypatch.setattr(bootstrap, "http_ok", lambda url, timeout=5.0: seen.append(url) or True)
    runner = bootstrap.BuildRunner(project.docker_dir, argv=OK_ARGV, env=child_env(), poll_interval=0.01,
                                   frontend_wait=0.05)
    runner.start()
    runner.wait(10)
    assert runner.state == "healthy"
    assert seen[:2] == [bootstrap.HEALTH_URL, bootstrap.FRONTEND_URL]


def test_build_subprocess_gets_the_minimal_env(project):
    argv = [sys.executable, "-c", "import os, json; print(json.dumps(sorted(os.environ)))"]
    env = bootstrap.build_env({"PATH": os.environ.get("PATH", ""), "HOME": "/tmp",
                               "SECRET_KEY": "leak", "ANTHROPIC_API_KEY": "sk-leak"})
    runner = bootstrap.BuildRunner(project.docker_dir, argv=argv, env=env, probe=lambda url: True,
                                   frontend_url=None)
    runner.start()
    runner.wait(10)
    names = json.loads(next(line for line in runner.status(0)["lines"] if line.startswith("[")))
    assert "SECRET_KEY" not in names and "ANTHROPIC_API_KEY" not in names
    assert {"PATH", "HOME", "COMPOSE_ANSI"} <= set(names)


def test_status_pages_through_a_capped_ring_buffer(project):
    runner = make_runner(project, max_lines=50)
    for i in range(120):
        runner._append(f"line {i}\n")

    first = runner.status(0)
    assert first["lines"][0] == "line 70" and first["lines"][-1] == "line 119"
    assert first["next"] == 120
    assert runner.status(100)["lines"] == [f"line {i}" for i in range(100, 120)]
    past_the_end = runner.status(500)
    assert past_the_end["lines"] == [] and past_the_end["next"] == 120


def test_ansi_and_carriage_returns_are_cleaned(project):
    runner = make_runner(project)
    runner._append("\x1b[32m Container docker-db-1  Started\x1b[0m\n")
    runner._append("progress 10%\rprogress 100%\n")
    assert runner.status(0)["lines"] == [" Container docker-db-1  Started", "progress 100%"]


def test_diagnose_recognises_common_failures():
    assert "isn't running" in bootstrap.diagnose(["Cannot connect to the Docker daemon at unix:///x"])
    assert "disk space" in bootstrap.diagnose(["write /var/lib: no space left on device"])
    assert "step 2" in bootstrap.diagnose(["env file /p/backend/.env not found: stat"])
    assert bootstrap.diagnose(["all good"]) is None


# ── open / quit / misc ───────────────────────────────────────────────────────


def test_open_start_docker_and_quit(serve):
    opened, started = [], []
    server = serve(open_url=lambda url: opened.append(url) or True,
                   start_docker=lambda: started.append(1) or True)

    assert server.request("POST", "/api/open", {})[1] == {"ok": True, "url": "http://localhost:3000"}
    assert opened == ["http://localhost:3000"]
    assert server.request("POST", "/api/start-docker", {})[1] == {"ok": True}
    assert started == [1]

    status, body, _ = server.request("POST", "/api/quit", {})
    assert (status, body) == (200, {"ok": True})
    server.thread.join(timeout=5)
    assert not server.thread.is_alive()


def test_make_server_falls_back_to_the_next_port(project):
    blocker = socket.socket()
    blocker.bind(("127.0.0.1", 0))
    blocker.listen()
    taken = blocker.getsockname()[1]
    app = bootstrap.InstallerApp(project, TOKEN, preflight=fake_preflight(project),
                                 runner=make_runner(project))
    try:
        server = bootstrap.make_server(app, ports=[taken, 0])
        try:
            assert app.port != taken and server.server_address[0] == "127.0.0.1"
        finally:
            server.server_close()
    finally:
        blocker.close()


def test_configure_logging_creates_a_private_log(tmp_path):
    log_file = tmp_path / "bootstrap.log"
    handlers = bootstrap.configure_logging(log_file)
    logger = logging.getLogger(bootstrap.LOGGER_NAME)
    try:
        logger.info("hello from the test")
    finally:
        for handler in handlers:
            logger.removeHandler(handler)
            handler.close()
    assert stat.S_IMODE(log_file.stat().st_mode) == 0o600
    assert "hello from the test" in log_file.read_text()


def test_check_only_prints_json(monkeypatch, capsys):
    monkeypatch.setattr(bootstrap.Preflight, "check", lambda self: {"docker_installed": False})
    logger = logging.getLogger(bootstrap.LOGGER_NAME)
    before = list(logger.handlers)
    try:
        assert bootstrap.main(["--check-only", "--no-browser", "--port", "3999"]) == 0
    finally:
        for handler in list(logger.handlers):
            if handler not in before:
                logger.removeHandler(handler)
    assert json.loads(capsys.readouterr().out) == {"docker_installed": False}


# ── static files ─────────────────────────────────────────────────────────────


def test_page_loads_no_external_resources():
    html = (INSTALLER_DIR / "page.html").read_text(encoding="utf-8")
    urls = set(re.findall(r"https?://[^\s\"'<>)]+", html))
    assert urls <= {bootstrap.DOCKER_DESKTOP_URL, "http://localhost:3000"}, urls
    assert bootstrap.DOCKER_DESKTOP_URL in urls
    lowered = html.lower()
    assert "<script src" not in lowered and "@import" not in lowered and "url(" not in lowered
    assert not re.search(r"<link[^>]+stylesheet", lowered)
    assert re.search(r'<link rel="icon" href="data:,">', html)
    assert html.count('nonce="__CSP_NONCE__"') == 2
    assert "innerHTML" not in html


def test_page_words_things_for_both_platforms():
    html = (INSTALLER_DIR / "page.html").read_text(encoding="utf-8")
    for text in ("Install Crawler AI.command", "Install Crawler AI.bat", "WSL 2",
                 "Docker Desktop for Mac", "Docker Desktop for Windows"):
        assert text in html, text


def test_command_file_launches_the_bootstrap():
    command = PROJECT_DIR / "Install Crawler AI.command"
    raw = command.read_bytes()
    assert b"\r\n" not in raw  # bash chokes on CRLF
    text = raw.decode()
    assert text.startswith("#!/bin/bash\n")
    if os.name != "nt":
        assert os.stat(command).st_mode & 0o111 == 0o111
    assert 'cd "$(dirname "$0")"' in text
    assert "xcode-select --install" in text
    assert text.rstrip().endswith('exec python3 installer/bootstrap.py "$@"')


def test_bat_file_launches_the_bootstrap_on_windows():
    raw = (PROJECT_DIR / "Install Crawler AI.bat").read_bytes()
    # cmd.exe mis-parses labels in LF-only batch files; every line ends CRLF.
    assert raw.count(b"\n") == raw.count(b"\r\n") > 0
    text = raw.decode("ascii")  # plain ASCII: cmd.exe reads it in the OEM code page
    assert text.lower().startswith("@echo off")
    assert 'cd /d "%~dp0"' in text
    assert "py -3 installer\\bootstrap.py %*" in text
    assert "python installer\\bootstrap.py %*" in text
    assert text.index("py -3 installer") < text.index("python installer")
    assert "Microsoft Store" in text and "Add python.exe to PATH" in text
    assert 'start "" "https://www.python.org/downloads/"' in text
    assert "pause" in text

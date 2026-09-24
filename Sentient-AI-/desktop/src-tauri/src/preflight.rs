//! Step 1 of setup, "Check this computer": is Docker installed and running, is Compose
//! v2 there, are the four ports free, is there disk space, is a Crawler AI stack already
//! set up. Also home of the `CommandRunner` trait every child process goes through.
//!
//! Why it exists: the checks and their plain-English fixes mirror
//! installer/bootstrap.py's `Preflight` so the app and the bootstrap tell a user the same
//! thing. All external commands run through `CommandRunner` (argv arrays, no shell, an
//! allowlisted environment, a timeout), which is also the seam the tests fake.

use std::collections::BTreeMap;
use std::io::{self, BufRead, BufReader, Read};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::platform::{self, Os, DOCKER_DESKTOP_URL};
use crate::stack::COMPOSE_PROJECT;

pub const CHECK_TIMEOUT: Duration = Duration::from_secs(10);
pub const MIN_FREE_DISK_GB: f64 = 10.0;
/// (port, what uses it): the host ports docker/docker-compose.yml publishes.
pub const APP_PORTS: &[(u16, &str)] = &[
    (3000, "web app"),
    (8000, "API"),
    (5432, "database"),
    (6379, "Redis"),
];
/// Collected output per stream for `run` (compose ls JSON, versions) is capped.
const MAX_CAPTURE_BYTES: usize = 1024 * 1024;

// ── Running commands ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CmdError {
    #[error("program not found")]
    NotFound,
    #[error("timed out")]
    Timeout,
    #[error("cancelled")]
    Cancelled,
    #[error("{0}")]
    Io(String),
}

/// What a child process did. `error` is set when it could not start, timed out or was
/// cancelled; otherwise `code` is its exit code (None if a signal ended it).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CmdOutput {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub error: Option<CmdError>,
}

impl CmdOutput {
    pub fn exited(code: i32, stdout: &str) -> Self {
        Self {
            code: Some(code),
            stdout: stdout.to_string(),
            ..Self::default()
        }
    }

    pub fn failed(error: CmdError) -> Self {
        Self {
            error: Some(error),
            ..Self::default()
        }
    }

    pub fn ok(&self) -> bool {
        self.error.is_none() && self.code == Some(0)
    }

    /// Short reason for a log line or error message ("exit code 1", "timed out").
    pub fn describe_failure(&self) -> String {
        match (&self.error, self.code) {
            (Some(err), _) => err.to_string(),
            (None, Some(code)) => format!("exit code {code}"),
            (None, None) => "stopped by a signal".to_string(),
        }
    }
}

/// Every external program the app runs goes through this: argv arrays only (never a
/// shell), a timeout, and the runner's allowlisted environment.
pub trait CommandRunner: Send + Sync {
    /// Resolve a program on the runner's PATH.
    fn which(&self, program: &str) -> Option<PathBuf>;
    /// Run to completion and capture stdout/stderr.
    fn run(&self, argv: &[String], cwd: Option<&Path>, timeout: Duration) -> CmdOutput;
    /// Run to completion, handing each stdout/stderr line (without its line ending) to
    /// `on_line` as it arrives. Setting `cancel` kills the process.
    fn stream(
        &self,
        argv: &[String],
        cwd: Option<&Path>,
        timeout: Duration,
        cancel: &AtomicBool,
        on_line: &mut dyn FnMut(&str),
    ) -> CmdOutput;
    /// Start a program that outlives this call (Docker Desktop, the browser).
    fn spawn_detached(&self, argv: &[String]) -> Result<(), CmdError>;
}

/// The real runner: `std::process::Command` with `env_clear()` + the allowlisted env.
pub struct SystemRunner {
    os: Os,
    env: BTreeMap<String, String>,
}

impl SystemRunner {
    pub fn new(os: Os, env: BTreeMap<String, String>) -> Self {
        Self { os, env }
    }

    /// A runner for this OS whose environment is the allowlisted slice of ours.
    pub fn for_this_process() -> Self {
        let os = Os::current();
        let env = platform::build_env(os, &platform::process_env(), dirs::home_dir().as_deref());
        Self::new(os, env)
    }

    pub fn env(&self) -> &BTreeMap<String, String> {
        &self.env
    }

    fn command(&self, argv: &[String], cwd: Option<&Path>) -> Result<Command, CmdError> {
        let (program, args) = argv
            .split_first()
            .ok_or_else(|| CmdError::Io("empty command".into()))?;
        let mut cmd = Command::new(program);
        cmd.args(args)
            .env_clear()
            .envs(&self.env)
            .stdin(Stdio::null());
        if let Some(dir) = cwd {
            cmd.current_dir(dir);
        }
        Ok(cmd)
    }

    fn spawn_piped(&self, argv: &[String], cwd: Option<&Path>) -> Result<Child, CmdError> {
        let mut cmd = self.command(argv, cwd)?;
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        hide_console(&mut cmd);
        cmd.spawn().map_err(spawn_error)
    }
}

fn spawn_error(err: io::Error) -> CmdError {
    if err.kind() == io::ErrorKind::NotFound {
        CmdError::NotFound
    } else {
        CmdError::Io(err.to_string())
    }
}

/// A GUI app must not flash a console window for every `docker` call on Windows.
#[cfg(windows)]
fn hide_console(cmd: &mut Command) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    cmd.creation_flags(CREATE_NO_WINDOW);
}

#[cfg(not(windows))]
fn hide_console(_cmd: &mut Command) {}

#[cfg(windows)]
fn detach(cmd: &mut Command) {
    use std::os::windows::process::CommandExt;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
}

#[cfg(unix)]
fn detach(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    cmd.process_group(0);
}

#[cfg(not(any(unix, windows)))]
fn detach(_cmd: &mut Command) {}

enum Pipe {
    Line { stderr: bool, text: String },
    Eof,
}

fn pump<R: Read + Send + 'static>(reader: R, stderr: bool, tx: Sender<Pipe>) {
    thread::spawn(move || {
        let mut reader = BufReader::new(reader);
        let mut buf = Vec::new();
        loop {
            buf.clear();
            match reader.read_until(b'\n', &mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let text = String::from_utf8_lossy(&buf).into_owned();
                    if tx.send(Pipe::Line { stderr, text }).is_err() {
                        return;
                    }
                }
            }
        }
        let _ = tx.send(Pipe::Eof);
    });
}

fn push_capped(target: &mut String, text: &str) {
    if target.len() < MAX_CAPTURE_BYTES {
        target.push_str(text);
    }
}

fn wait_until(child: &mut Child, limit: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + limit;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            Ok(None) | Err(_) => {
                let _ = child.kill();
                return child.wait().ok();
            }
        }
    }
}

/// Read both pipes until they close, enforcing `timeout` and `cancel`. Lines go to
/// `on_line` when given, otherwise into the returned stdout/stderr.
fn drive(
    mut child: Child,
    timeout: Duration,
    cancel: Option<&AtomicBool>,
    mut on_line: Option<&mut dyn FnMut(&str)>,
) -> CmdOutput {
    let (tx, rx) = mpsc::channel();
    let mut open = 0;
    if let Some(out) = child.stdout.take() {
        pump(out, false, tx.clone());
        open += 1;
    }
    if let Some(err) = child.stderr.take() {
        pump(err, true, tx.clone());
        open += 1;
    }
    drop(tx);

    let deadline = Instant::now() + timeout;
    let mut result = CmdOutput::default();
    let mut killed_at: Option<Instant> = None;
    let mut exited_at: Option<Instant> = None;
    while open > 0 {
        let now = Instant::now();
        if killed_at.is_none() {
            let reason = if cancel.is_some_and(|c| c.load(Ordering::SeqCst)) {
                Some(CmdError::Cancelled)
            } else if now >= deadline {
                Some(CmdError::Timeout)
            } else {
                None
            };
            if let Some(reason) = reason {
                result.error = Some(reason);
                let _ = child.kill();
                killed_at = Some(now);
            }
        }
        // A grandchild can keep a pipe open after the process itself is gone: stop
        // reading 5 s after a kill, or once the output has gone quiet 2 s after exit.
        if exited_at.is_none() && matches!(child.try_wait(), Ok(Some(_))) {
            exited_at = Some(now);
        }
        let grace_over = |t: Option<Instant>, secs| {
            t.is_some_and(|t| now.duration_since(t) > Duration::from_secs(secs))
        };
        if grace_over(killed_at, 5) {
            break;
        }
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(Pipe::Line { stderr, text }) => match on_line.as_mut() {
                Some(callback) => callback(text.trim_end_matches(['\n', '\r'])),
                None if stderr => push_capped(&mut result.stderr, &text),
                None => push_capped(&mut result.stdout, &text),
            },
            Ok(Pipe::Eof) => open -= 1,
            Err(RecvTimeoutError::Timeout) if grace_over(exited_at, 2) => break,
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    // Pipes closed: the process is exiting. Give it a minute (5 s after a kill).
    let limit = Duration::from_secs(if killed_at.is_some() { 5 } else { 60 });
    let status = wait_until(&mut child, limit);
    if result.error.is_none() {
        result.code = status.and_then(|s| s.code());
    }
    result
}

impl CommandRunner for SystemRunner {
    fn which(&self, program: &str) -> Option<PathBuf> {
        let path = self.env.get("PATH").map(String::as_str).unwrap_or("");
        platform::which_in(program, path, self.os)
    }

    fn run(&self, argv: &[String], cwd: Option<&Path>, timeout: Duration) -> CmdOutput {
        match self.spawn_piped(argv, cwd) {
            Ok(child) => drive(child, timeout, None, None),
            Err(err) => CmdOutput::failed(err),
        }
    }

    fn stream(
        &self,
        argv: &[String],
        cwd: Option<&Path>,
        timeout: Duration,
        cancel: &AtomicBool,
        on_line: &mut dyn FnMut(&str),
    ) -> CmdOutput {
        match self.spawn_piped(argv, cwd) {
            Ok(child) => drive(child, timeout, Some(cancel), Some(on_line)),
            Err(err) => CmdOutput::failed(err),
        }
    }

    fn spawn_detached(&self, argv: &[String]) -> Result<(), CmdError> {
        let mut cmd = self.command(argv, None)?;
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
        detach(&mut cmd);
        let mut child = cmd.spawn().map_err(spawn_error)?;
        // Reap it when it exits so it never lingers as a zombie.
        thread::spawn(move || {
            let _ = child.wait();
        });
        Ok(())
    }
}

// ── Parsing ──────────────────────────────────────────────────────────────────

fn first_line(text: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(|l| l.chars().take(200).collect())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ComposeVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

/// Parse `docker compose version [--short]` output: "2.29.1", "v2.29.1",
/// "Docker Compose version v2.24.6-desktop.1", "docker-compose version 1.29.2, build x".
pub fn parse_compose_version(stdout: &str) -> Option<ComposeVersion> {
    let line = first_line(stdout)?;
    line.split(|c: char| c.is_whitespace() || c == ',')
        .map(|tok| tok.strip_prefix(['v', 'V']).unwrap_or(tok))
        .find(|tok| tok.starts_with(|c: char| c.is_ascii_digit()) && tok.contains('.'))
        .and_then(|tok| {
            let mut nums = tok.split('.').map(|part| {
                let digits: String = part.chars().take_while(char::is_ascii_digit).collect();
                digits.parse::<u32>().ok()
            });
            let major = nums.next()??;
            let minor = nums.next().flatten().unwrap_or(0);
            let patch = nums.next().flatten().unwrap_or(0);
            Some(ComposeVersion {
                major,
                minor,
                patch,
            })
        })
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct StackConflict {
    pub name: String,
    pub status: String,
    /// The project folder (the one holding docker/) of the other stack.
    pub folder: String,
    /// The other stack is an earlier version installed by this app (same stack root).
    pub earlier_app_version: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct StackInfo {
    /// A Compose project built from this version's compose file, under any name.
    pub existing_stack: bool,
    pub existing_stack_status: Option<String>,
    pub existing_stack_name: Option<String>,
    /// A different folder's project using our project name; building here would
    /// recreate its containers (the named volumes, and so the data, are shared).
    pub stack_conflict: Option<StackConflict>,
}

/// Lexically clean an absolute path (`.`/`..`), for paths that do not exist yet.
fn lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn comparable(path: &Path, os: Os) -> String {
    let resolved = std::fs::canonicalize(path).unwrap_or_else(|_| lexical(path));
    let text = resolved.to_string_lossy();
    let text = text.strip_prefix(r"\\?\").unwrap_or(&text).to_string();
    if os == Os::Windows {
        text.replace('/', "\\").to_lowercase()
    } else {
        text
    }
}

fn same_file(a: &str, b: &Path, os: Os) -> bool {
    comparable(Path::new(a), os) == comparable(b, os)
}

fn is_within(child: &str, root: &Path, os: Os) -> bool {
    let child = comparable(Path::new(child), os);
    let root = comparable(root, os);
    let sep = if os == Os::Windows { '\\' } else { '/' };
    child.len() > root.len() && child.starts_with(&root) && child[root.len()..].starts_with(sep)
}

/// Parse `docker compose ls --all --format json` (same semantics as bootstrap.py's
/// find_stack). `stack_root` marks a conflicting stack from an earlier app version.
pub fn find_stack(
    ls_json: &str,
    compose_file: &Path,
    stack_root: Option<&Path>,
    os: Os,
) -> StackInfo {
    let mut info = StackInfo::default();
    let text = if ls_json.trim().is_empty() {
        "[]"
    } else {
        ls_json
    };
    let Ok(serde_json::Value::Array(projects)) = serde_json::from_str::<serde_json::Value>(text)
    else {
        return info;
    };
    let field = |p: &serde_json::Value, key: &str, max: usize| -> String {
        let s = match p.get(key) {
            Some(serde_json::Value::String(s)) => s.clone(),
            Some(serde_json::Value::Null) | None => String::new(),
            Some(other) => other.to_string(),
        };
        s.chars().take(max).collect()
    };
    for project in projects.iter().filter(|p| p.is_object()) {
        let name = field(project, "Name", 80);
        let status = field(project, "Status", 80);
        let files_raw = field(project, "ConfigFiles", 4096);
        let files: Vec<&str> = files_raw
            .split(',')
            .map(str::trim)
            .filter(|f| !f.is_empty())
            .collect();
        if files.iter().any(|f| same_file(f, compose_file, os)) {
            info.existing_stack = true;
            info.existing_stack_status = Some(status);
            info.existing_stack_name = Some(name);
        } else if name.to_lowercase() == COMPOSE_PROJECT {
            let folder = files
                .first()
                .and_then(|f| split_parent(f, os))
                .and_then(|docker_dir| split_parent(&docker_dir, os))
                .unwrap_or_default();
            let earlier =
                stack_root.is_some_and(|root| !folder.is_empty() && is_within(&folder, root, os));
            info.stack_conflict = Some(StackConflict {
                name,
                status,
                folder: folder.chars().take(300).collect(),
                earlier_app_version: earlier,
            });
        }
    }
    info
}

/// Parent of a path string as reported by Compose (which may be a Windows path even
/// when these tests run on a Mac).
fn split_parent(path: &str, os: Os) -> Option<String> {
    let seps: &[char] = if os == Os::Windows {
        &['\\', '/']
    } else {
        &['/']
    };
    let trimmed = path.trim_end_matches(seps);
    let idx = trimmed.rfind(seps)?;
    let parent = &trimmed[..idx];
    Some(if parent.is_empty() || parent.ends_with(':') {
        format!("{parent}{}", &trimmed[idx..=idx])
    } else {
        parent.to_string()
    })
}

// ── Ports ────────────────────────────────────────────────────────────────────

/// True when nothing listens on `port` and Docker could publish it: nothing accepts a
/// connection on 127.0.0.1 and both 127.0.0.1 and 0.0.0.0 can be bound.
pub fn port_is_free(port: u16) -> bool {
    let loopback = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    if TcpStream::connect_timeout(&loopback, Duration::from_millis(300)).is_ok() {
        return false;
    }
    for ip in [Ipv4Addr::LOCALHOST, Ipv4Addr::UNSPECIFIED] {
        if let Err(err) = TcpListener::bind((ip, port)) {
            if err.kind() == io::ErrorKind::AddrInUse {
                return false;
            }
        }
    }
    true
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Holder {
    pub holder: String,
    pub docker: bool,
}

// lsof truncates COMMAND to 9 characters, so Docker Desktop's com.docker.backend shows
// up as "com.docke"; on Windows it is com.docker.backend.exe.
const DOCKER_PROCESSES: &[&str] = &["com.docke", "vpnkit", "docker"];

fn holders(entries: &[(String, String)]) -> Option<Holder> {
    let mut labels: Vec<String> = Vec::new();
    let mut docker = false;
    for (command, pid) in entries {
        let is_docker = DOCKER_PROCESSES
            .iter()
            .any(|p| command.to_lowercase().starts_with(p));
        let label = if is_docker {
            format!("Docker Desktop (pid {pid})")
        } else {
            format!("{command} (pid {pid})")
        };
        docker |= is_docker;
        if !labels.contains(&label) {
            labels.push(label);
        }
    }
    if labels.is_empty() {
        return None;
    }
    labels.truncate(3);
    Some(Holder {
        holder: labels.join(", "),
        docker,
    })
}

/// `lsof -nP -iTCP:<port> -sTCP:LISTEN` output -> who holds the port.
pub fn parse_lsof(output: &str) -> Option<Holder> {
    let entries: Vec<(String, String)> = output
        .lines()
        .skip(1)
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let command = parts.next()?;
            let pid = parts.next()?;
            pid.chars().all(|c| c.is_ascii_digit()).then(|| {
                (
                    command.replace("\\x20", " ").chars().take(40).collect(),
                    pid.to_string(),
                )
            })
        })
        .collect();
    holders(&entries)
}

/// PIDs listening on `port` in `netstat -ano` output (Windows). State names are
/// localised, so a listener is recognised by its foreign address 0.0.0.0:0 / [::]:0.
pub fn parse_netstat(output: &str, port: u16) -> Vec<String> {
    let suffix = format!(":{port}");
    let mut pids: Vec<String> = Vec::new();
    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 || !parts[0].eq_ignore_ascii_case("TCP") {
            continue;
        }
        let (local, foreign, pid) = (parts[1], parts[2], parts[parts.len() - 1]);
        let listening = local.ends_with(&suffix) && (foreign == "0.0.0.0:0" || foreign == "[::]:0");
        let numeric = !pid.is_empty() && pid.chars().all(|c| c.is_ascii_digit());
        if listening && numeric && pid != "0" && !pids.iter().any(|p| p == pid) {
            pids.push(pid.to_string());
        }
    }
    pids
}

fn csv_fields(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => fields.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    fields.push(cur);
    fields
}

/// Image name from `tasklist /FI "PID eq N" /FO CSV /NH` output (Windows).
pub fn parse_tasklist(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let fields = csv_fields(line);
        let pid = fields.get(1)?.trim();
        (!pid.is_empty() && pid.chars().all(|c| c.is_ascii_digit()))
            .then(|| fields[0].trim().chars().take(60).collect())
    })
}

// ── Disk ─────────────────────────────────────────────────────────────────────

/// Free GB (one decimal) on the volume holding `path` or its nearest existing
/// ancestor; -1.0 when unknown.
pub fn disk_free_gb(path: &Path) -> f64 {
    let existing = path.ancestors().find(|p| p.exists());
    match existing.map(fs4::available_space) {
        Some(Ok(bytes)) => (bytes as f64 / 1024f64.powi(3) * 10.0).round() / 10.0,
        _ => -1.0,
    }
}

// ── The check ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PortReport {
    pub port: u16,
    pub service: String,
    pub free: bool,
    pub holder: Option<String>,
    pub docker: bool,
    /// Held by Docker while our own stack is running: expected, not a problem.
    pub ours: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FixLink {
    pub href: String,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Fix {
    pub id: String,
    /// "error" blocks installing, "warning" probably will, "info" is a heads-up.
    pub severity: String,
    pub text: String,
    pub link: Option<FixLink>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PreflightReport {
    pub os: Os,
    pub docker_installed: bool,
    pub docker_version: Option<String>,
    pub docker_running: bool,
    pub compose_v2: bool,
    pub compose_version: Option<String>,
    pub ports: Vec<PortReport>,
    pub disk_free_gb: f64,
    pub env_exists: bool,
    pub env_keys_set: bool,
    #[serde(flatten)]
    pub stack: StackInfo,
    /// Docker is running and Compose v2 is there: installing can start.
    pub ready: bool,
    pub fixes: Vec<Fix>,
}

type PortFree<'a> = Box<dyn Fn(u16) -> bool + Send + Sync + 'a>;
type DiskFree<'a> = Box<dyn Fn() -> f64 + Send + Sync + 'a>;

/// Read-only checks: what is installed, running, free and configured.
pub struct Preflight<'a> {
    pub os: Os,
    pub runner: &'a dyn CommandRunner,
    /// This version's docker/docker-compose.yml (it may not exist yet).
    pub compose_file: PathBuf,
    /// This version's backend/.env (it may not exist yet).
    pub env_file: PathBuf,
    pub stack_root: Option<PathBuf>,
    pub ports: Vec<(u16, String)>,
    pub port_free: PortFree<'a>,
    pub disk_free_gb: DiskFree<'a>,
}

impl<'a> Preflight<'a> {
    /// Real port and disk probes for the app's four ports.
    pub fn new(
        os: Os,
        runner: &'a dyn CommandRunner,
        compose_file: PathBuf,
        env_file: PathBuf,
        stack_root: Option<PathBuf>,
    ) -> Self {
        let disk_path = stack_root.clone().unwrap_or_else(|| env_file.clone());
        Self {
            os,
            runner,
            compose_file,
            env_file,
            stack_root,
            ports: APP_PORTS.iter().map(|(p, s)| (*p, s.to_string())).collect(),
            port_free: Box::new(port_is_free),
            disk_free_gb: Box::new(move || disk_free_gb(&disk_path)),
        }
    }

    fn port_holder(&self, port: u16) -> Option<Holder> {
        if self.os == Os::Windows {
            let netstat = self.runner.which("netstat")?;
            let out = self.runner.run(
                &[netstat.to_string_lossy().into_owned(), "-ano".into()],
                None,
                CHECK_TIMEOUT,
            );
            let tasklist = self.runner.which("tasklist");
            let entries: Vec<(String, String)> = parse_netstat(&out.stdout, port)
                .into_iter()
                .take(3)
                .map(|pid| {
                    let name = tasklist.as_ref().and_then(|t| {
                        let argv = vec![
                            t.to_string_lossy().into_owned(),
                            "/FI".into(),
                            format!("PID eq {pid}"),
                            "/FO".into(),
                            "CSV".into(),
                            "/NH".into(),
                        ];
                        parse_tasklist(&self.runner.run(&argv, None, CHECK_TIMEOUT).stdout)
                    });
                    (name.unwrap_or_else(|| "a program".into()), pid)
                })
                .collect();
            return holders(&entries);
        }
        let lsof = self
            .runner
            .which("lsof")
            .or_else(|| Some(PathBuf::from("/usr/sbin/lsof")).filter(|p| p.exists()))?;
        let argv = vec![
            lsof.to_string_lossy().into_owned(),
            "-nP".into(),
            format!("-iTCP:{port}"),
            "-sTCP:LISTEN".into(),
        ];
        let out = self.runner.run(&argv, None, Duration::from_secs(5));
        parse_lsof(&out.stdout)
    }

    pub fn check(&self) -> PreflightReport {
        let mut report = PreflightReport {
            os: self.os,
            docker_installed: false,
            docker_version: None,
            docker_running: false,
            compose_v2: false,
            compose_version: None,
            ports: Vec::new(),
            disk_free_gb: (self.disk_free_gb)(),
            env_exists: self.env_file.exists(),
            env_keys_set: false,
            stack: StackInfo::default(),
            ready: false,
            fixes: Vec::new(),
        };
        if let Some(docker) = self.runner.which("docker") {
            let docker = docker.to_string_lossy().into_owned();
            let arg = |rest: &[&str]| -> Vec<String> {
                std::iter::once(docker.clone())
                    .chain(rest.iter().map(|s| s.to_string()))
                    .collect()
            };
            let version = self.runner.run(&arg(&["--version"]), None, CHECK_TIMEOUT);
            report.docker_installed = version.ok();
            report.docker_version = if version.ok() {
                first_line(&version.stdout)
            } else {
                None
            };
            if report.docker_installed {
                let info = self.runner.run(
                    &arg(&["info", "--format", "{{.ServerVersion}}"]),
                    None,
                    CHECK_TIMEOUT,
                );
                report.docker_running = info.ok() && !info.stdout.trim().is_empty();
                let compose = self.runner.run(
                    &arg(&["compose", "version", "--short"]),
                    None,
                    CHECK_TIMEOUT,
                );
                // The `docker compose` plugin only exists from v2 on; a parsed major < 2
                // (an odd shim) still counts as missing.
                let parsed = parse_compose_version(&compose.stdout);
                report.compose_v2 = compose.ok() && parsed.is_none_or(|v| v.major >= 2);
                report.compose_version = if compose.ok() {
                    first_line(&compose.stdout)
                } else {
                    None
                };
            }
            if report.docker_running && report.compose_v2 {
                let listing = self.runner.run(
                    &arg(&["compose", "ls", "--all", "--format", "json"]),
                    None,
                    CHECK_TIMEOUT,
                );
                if listing.ok() {
                    report.stack = find_stack(
                        &listing.stdout,
                        &self.compose_file,
                        self.stack_root.as_deref(),
                        self.os,
                    );
                }
            }
        }

        let stack_running = report.stack.existing_stack
            && report
                .stack
                .existing_stack_status
                .as_deref()
                .unwrap_or("")
                .starts_with("running");
        for (port, service) in &self.ports {
            let mut entry = PortReport {
                port: *port,
                service: service.clone(),
                free: true,
                holder: None,
                docker: false,
                ours: false,
            };
            if !(self.port_free)(*port) {
                entry.free = false;
                if let Some(holder) = self.port_holder(*port) {
                    entry.holder = Some(holder.holder);
                    entry.docker = holder.docker;
                    entry.ours = holder.docker && stack_running;
                }
            }
            report.ports.push(entry);
        }

        if report.env_exists {
            let status = crate::keys::env_key_status(&self.env_file);
            report.env_keys_set = status.secret_key && status.encryption_key;
        }
        report.ready = report.docker_running && report.compose_v2;
        report.fixes = fixes(&report);
        report
    }
}

fn fix(id: &str, severity: &str, text: String, link: Option<(&str, &str)>) -> Fix {
    Fix {
        id: id.into(),
        severity: severity.into(),
        text,
        link: link.map(|(href, label)| FixLink {
            href: href.into(),
            label: label.into(),
        }),
    }
}

fn port_fix_text(port: &PortReport, stack_conflict: bool) -> String {
    let place = format!("Port {} ({})", port.port, port.service);
    let consequence = format!("or Crawler AI's {} can't start.", port.service);
    match port.holder.as_deref() {
        Some(holder) if port.docker && !holder.contains(',') => {
            let likely = if stack_conflict {
                " (probably the other Crawler AI copy below)"
            } else {
                ""
            };
            format!(
                "{place} is already taken by a Docker container{likely}. Stop that container in \
                 Docker Desktop before installing, {consequence}"
            )
        }
        Some(holder) => {
            let them = if holder.contains(',') { "them" } else { "it" };
            format!("{place} is in use by {holder}. Quit {them} before installing, {consequence}")
        }
        None => {
            format!("{place} is in use by another app. Quit it before installing, {consequence}")
        }
    }
}

/// Plain-English next steps for a report (the setup window shows them as-is).
pub fn fixes(r: &PreflightReport) -> Vec<Fix> {
    let mut out = Vec::new();
    let download = Some((DOCKER_DESKTOP_URL, "Download Docker Desktop"));
    if !r.docker_installed {
        let text = match r.os {
            Os::Mac => "Docker Desktop isn't installed. Download Docker Desktop for Mac (pick Apple \
                        chip or Intel chip), drag it into Applications, open it once and accept its \
                        terms, then click Check again.",
            Os::Windows => "Docker Desktop isn't installed. Download Docker Desktop for Windows and \
                            run it; keep \"Use WSL 2\" ticked (Docker Desktop needs WSL 2) and restart \
                            if it asks. Open Docker Desktop once and accept its terms, then click \
                            Check again.",
            Os::Linux => "Docker isn't installed. Install Docker Desktop for Linux (or Docker Engine \
                          with the Compose plugin), then click Check again.",
        };
        out.push(fix("docker_installed", "error", text.into(), download));
    } else if !r.docker_running {
        let text = match r.os {
            Os::Mac => {
                "Docker Desktop is installed but not running. Click Open Docker Desktop and \
                        wait until it says Running (the whale in the menu bar stops moving), then \
                        click Check again."
            }
            Os::Windows => {
                "Docker Desktop is installed but not running. Click Open Docker Desktop \
                            and wait until it says Engine running. If it asks to install or update \
                            WSL 2, follow its prompt and restart. Then click Check again."
            }
            Os::Linux => {
                "Docker is installed but not running. Start Docker Desktop (or the docker \
                          service), then click Check again."
            }
        };
        out.push(fix("docker_running", "error", text.into(), None));
    }
    if r.docker_installed && !r.compose_v2 {
        out.push(fix(
            "compose_v2",
            "error",
            "Docker Compose (v2 or newer) is missing. Update Docker Desktop to the latest version \
             (it checks for updates in its Settings), then click Check again."
                .into(),
            Some((DOCKER_DESKTOP_URL, "Get the latest Docker Desktop")),
        ));
    }
    for port in r.ports.iter().filter(|p| !p.free && !p.ours) {
        out.push(fix(
            "ports",
            "warning",
            port_fix_text(port, r.stack.stack_conflict.is_some()),
            None,
        ));
    }
    if r.disk_free_gb >= 0.0 && r.disk_free_gb < MIN_FREE_DISK_GB {
        out.push(fix(
            "disk",
            "warning",
            format!(
                "Only {} GB free. The first install downloads about 3.6 GB and needs roughly {:.0} \
                 GB of room; free some space first.",
                r.disk_free_gb, MIN_FREE_DISK_GB
            ),
            None,
        ));
    }
    if r.env_keys_set {
        out.push(fix(
            "env",
            "info",
            "Your security keys are already saved. You can skip to Install & start.".into(),
            None,
        ));
    } else if r.env_exists {
        out.push(fix(
            "env",
            "info",
            "backend/.env exists but its SECRET_KEY / ENCRYPTION_KEY aren't set yet. Step 2 fills \
             them in and keeps a backup."
                .into(),
            None,
        ));
    }
    if r.stack.existing_stack {
        let status = r.stack.existing_stack_status.clone().unwrap_or_default();
        let name = r.stack.existing_stack_name.clone().unwrap_or_default();
        if !name.is_empty() && name != COMPOSE_PROJECT {
            out.push(fix(
                "existing_stack",
                "warning",
                format!(
                    "A Crawler AI stack from this app's folder is already {} under the Compose \
                     project '{}' (started by hand). Installing creates a separate '{}' stack with \
                     its own database, which cannot start while the other one holds the ports. \
                     Stop the other one in Docker Desktop first.",
                    if status.is_empty() {
                        "present"
                    } else {
                        &status
                    },
                    name,
                    COMPOSE_PROJECT
                ),
                None,
            ));
        } else {
            out.push(fix(
                "existing_stack",
                "info",
                format!(
                    "Crawler AI is already set up ({}). Install & start updates it; your data is kept.",
                    if status.is_empty() { "stopped" } else { &status }
                ),
                None,
            ));
        }
    }
    if let Some(conflict) = &r.stack.stack_conflict {
        let status = if conflict.status.is_empty() {
            "stopped"
        } else {
            &conflict.status
        };
        if conflict.earlier_app_version {
            out.push(fix(
                "stack_conflict",
                "info",
                format!(
                    "An earlier version of Crawler AI is set up ({status}). Install & start \
                     upgrades it to this version; your data is kept."
                ),
                None,
            ));
        } else {
            let place = if conflict.folder.is_empty() {
                String::new()
            } else {
                format!(" ({})", conflict.folder)
            };
            out.push(fix(
                "stack_conflict",
                "warning",
                format!(
                    "Another copy of Crawler AI{place} is set up in Docker as \"{}\" ({status}). \
                     Installing here replaces its containers with this app's version (the data is \
                     kept). If you run that copy by hand, stop it in Docker Desktop first.",
                    conflict.name
                ),
                None,
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::FakeRunner;

    #[test]
    fn compose_versions() {
        let v = |s: &str| parse_compose_version(s).map(|v| (v.major, v.minor, v.patch));
        assert_eq!(v("2.29.1\n"), Some((2, 29, 1)));
        assert_eq!(v("v2.29.1"), Some((2, 29, 1)));
        assert_eq!(
            v("Docker Compose version v2.24.6-desktop.1"),
            Some((2, 24, 6))
        );
        assert_eq!(v("Docker Compose version 2.3"), Some((2, 3, 0)));
        assert_eq!(
            v("docker-compose version 1.29.2, build 5becea4c"),
            Some((1, 29, 2))
        );
        assert_eq!(v("\n  v5.0.0-rc.1\n"), Some((5, 0, 0)));
        assert_eq!(v(""), None);
        assert_eq!(v("unknown flag: --short"), None);
    }

    fn compose_path(dir: &Path) -> PathBuf {
        let docker = dir.join("docker");
        std::fs::create_dir_all(&docker).unwrap();
        let file = docker.join("docker-compose.yml");
        std::fs::write(&file, "services: {}\n").unwrap();
        file
    }

    #[test]
    fn find_stack_existing_by_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let ours = compose_path(dir.path());
        let json = serde_json::json!([
            {"Name": "crawler-ai", "Status": "running(4)", "ConfigFiles": ours.to_string_lossy()},
            {"Name": "unrelated", "Status": "exited(1)", "ConfigFiles": "/x/compose.yml"}
        ])
        .to_string();
        let info = find_stack(&json, &ours, None, Os::current());
        assert!(info.existing_stack);
        assert_eq!(info.existing_stack_status.as_deref(), Some("running(4)"));
        assert_eq!(info.existing_stack_name.as_deref(), Some("crawler-ai"));
        assert_eq!(info.stack_conflict, None);
    }

    #[test]
    fn find_stack_same_name_other_folder_is_conflict() {
        let dir = tempfile::tempdir().unwrap();
        let ours = compose_path(&dir.path().join("mine"));
        let other = compose_path(&dir.path().join("checkout"));
        let json = serde_json::json!([
            {"Name": "crawler-ai", "Status": "exited(4)", "ConfigFiles": other.to_string_lossy()},
        ])
        .to_string();
        let info = find_stack(&json, &ours, None, Os::current());
        assert!(!info.existing_stack);
        let conflict = info.stack_conflict.unwrap();
        assert_eq!(conflict.name, "crawler-ai");
        assert_eq!(conflict.status, "exited(4)");
        assert_eq!(PathBuf::from(&conflict.folder), dir.path().join("checkout"));
        assert!(!conflict.earlier_app_version);
    }

    #[test]
    fn find_stack_earlier_app_version_and_hand_started_stack() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("stack");
        let ours = compose_path(&root.join("1.1.0"));
        let old = compose_path(&root.join("1.0.0"));
        let json = serde_json::json!([
            {"Name": "CRAWLER-AI", "Status": "running(4)", "ConfigFiles": old.to_string_lossy()},
            {"Name": "docker", "Status": "exited(2)", "ConfigFiles": format!("{}, /x/override.yml", ours.display())},
        ])
        .to_string();
        let info = find_stack(&json, &ours, Some(&root), Os::current());
        assert!(info.existing_stack);
        assert_eq!(info.existing_stack_name.as_deref(), Some("docker"));
        let conflict = info.stack_conflict.unwrap();
        assert!(conflict.earlier_app_version);
        assert_eq!(conflict.name, "CRAWLER-AI");
    }

    #[test]
    fn find_stack_windows_paths_compare_case_insensitively() {
        let json = r#"[{"Name":"crawler-ai","Status":"running(4)","ConfigFiles":"C:\\Users\\Bob\\AppData\\Local\\Crawler AI\\stack\\1.0.0\\docker\\docker-compose.yml"}]"#;
        let ours = Path::new(
            r"c:\users\bob\appdata\local\crawler ai\stack\1.0.0\docker\docker-compose.yml",
        );
        let info = find_stack(json, ours, None, Os::Windows);
        assert!(info.existing_stack);
        let other = Path::new(
            r"C:\Users\Bob\AppData\Local\Crawler AI\stack\1.1.0\docker\docker-compose.yml",
        );
        let root = Path::new(r"C:\Users\Bob\AppData\Local\Crawler AI\stack");
        let info = find_stack(json, other, Some(root), Os::Windows);
        let conflict = info.stack_conflict.unwrap();
        assert_eq!(
            conflict.folder,
            r"C:\Users\Bob\AppData\Local\Crawler AI\stack\1.0.0"
        );
        assert!(conflict.earlier_app_version);
    }

    #[test]
    fn find_stack_tolerates_garbage() {
        let file = Path::new("/nope/docker/docker-compose.yml");
        for bad in ["", "not json", "{}", "[1, \"x\", null]", "[{\"Name\": 5}]"] {
            let info = find_stack(bad, file, None, Os::Mac);
            assert!(!info.existing_stack, "{bad}");
            assert_eq!(info.stack_conflict, None, "{bad}");
        }
    }

    #[test]
    fn lsof_netstat_tasklist() {
        let lsof = "COMMAND     PID  USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n\
                    com.docke 1234 krish  150u  IPv6 0x0      0t0  TCP *:3000 (LISTEN)\n\
                    node      99   krish  20u   IPv4 0x0      0t0  TCP 127.0.0.1:3000 (LISTEN)\n";
        let holder = parse_lsof(lsof).unwrap();
        assert_eq!(holder.holder, "Docker Desktop (pid 1234), node (pid 99)");
        assert!(holder.docker);
        assert_eq!(parse_lsof("COMMAND PID\n"), None);

        let netstat = "  Proto  Local Address   Foreign Address  State   PID\n\
                       TCP    0.0.0.0:3000    0.0.0.0:0        ABHÖREN  4242\n\
                       TCP    [::]:3000       [::]:0           LISTENING  4242\n\
                       TCP    127.0.0.1:3000  127.0.0.1:5555   ESTABLISHED  7\n\
                       TCP    0.0.0.0:30000   0.0.0.0:0        LISTENING  8\n";
        assert_eq!(parse_netstat(netstat, 3000), vec!["4242".to_string()]);
        assert_eq!(
            parse_tasklist(
                "\"com.docker.backend.exe\",\"4242\",\"Console\",\"1\",\"50,000 K\"\r\n"
            )
            .as_deref(),
            Some("com.docker.backend.exe")
        );
        assert_eq!(parse_tasklist("INFO: No tasks are running"), None);
    }

    #[test]
    fn port_probe_sees_a_listener_on_an_ephemeral_port() {
        // Other tests' outgoing loopback connections draw local ports from the same
        // ephemeral range, so they are kept from running alongside this one.
        let _net = crate::test_support::net_lock();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(!port_is_free(port));
        drop(listener);
        let freed = (0..20).any(|_| {
            let free = port_is_free(port);
            if !free {
                std::thread::sleep(Duration::from_millis(50));
            }
            free
        });
        assert!(
            freed,
            "port {port} still reported busy after its listener closed"
        );
    }

    #[test]
    fn disk_free_walks_up_to_an_existing_folder() {
        let dir = tempfile::tempdir().unwrap();
        let gb = disk_free_gb(&dir.path().join("not/yet/there"));
        assert!(gb >= 0.0);
    }

    fn preflight<'a>(runner: &'a FakeRunner, dir: &Path, busy: &'a [u16]) -> Preflight<'a> {
        Preflight {
            os: Os::Mac,
            runner,
            compose_file: dir.join("docker/docker-compose.yml"),
            env_file: dir.join("backend/.env"),
            stack_root: None,
            ports: vec![(41000, "web app".into()), (41001, "API".into())],
            port_free: Box::new(move |p| !busy.contains(&p)),
            disk_free_gb: Box::new(|| 50.0),
        }
    }

    #[test]
    fn check_without_docker() {
        let dir = tempfile::tempdir().unwrap();
        let runner = FakeRunner::new();
        runner.missing("docker");
        let report = preflight(&runner, dir.path(), &[]).check();
        assert!(!report.docker_installed && !report.ready);
        assert_eq!(report.fixes[0].id, "docker_installed");
        assert_eq!(report.fixes[0].severity, "error");
        assert_eq!(
            report.fixes[0].link.as_ref().unwrap().href,
            DOCKER_DESKTOP_URL
        );
        assert!(runner.calls().is_empty());
    }

    #[test]
    fn check_docker_not_running() {
        let dir = tempfile::tempdir().unwrap();
        let runner = FakeRunner::new();
        runner.respond(
            "docker --version",
            0,
            "Docker version 27.3.1, build ce12230\n",
        );
        runner.respond("docker info", 1, "");
        runner.respond("docker compose version", 0, "2.29.7\n");
        let report = preflight(&runner, dir.path(), &[]).check();
        assert!(report.docker_installed && !report.docker_running && report.compose_v2);
        assert_eq!(
            report.docker_version.as_deref(),
            Some("Docker version 27.3.1, build ce12230")
        );
        assert_eq!(report.compose_version.as_deref(), Some("2.29.7"));
        assert!(!report.ready);
        assert_eq!(report.fixes[0].id, "docker_running");
        assert!(!runner.calls().iter().any(|c| c.contains(&"ls".to_string())));
    }

    #[test]
    fn check_all_good_with_busy_port_and_existing_stack() {
        let dir = tempfile::tempdir().unwrap();
        let compose = compose_path(dir.path());
        let runner = FakeRunner::new();
        runner.respond("docker --version", 0, "Docker version 27.3.1\n");
        runner.respond("docker info", 0, "27.3.1\n");
        runner.respond("docker compose version", 0, "v2.29.7\n");
        let ls = serde_json::json!([{"Name": "crawler-ai", "Status": "running(4)", "ConfigFiles": compose.to_string_lossy()}]);
        runner.respond("docker compose ls", 0, &ls.to_string());
        runner.respond(
            "lsof",
            0,
            "COMMAND PID USER\ncom.docke 12 me 1u IPv4 TCP *:41001 (LISTEN)\n",
        );
        let busy = [41001u16];
        let report = preflight(&runner, dir.path(), &busy).check();
        assert!(report.ready);
        assert!(report.stack.existing_stack);
        assert!(report.ports[0].free);
        let api = &report.ports[1];
        assert!(!api.free && api.docker && api.ours);
        // Our own running stack holding the port is not a problem.
        assert!(!report.fixes.iter().any(|f| f.id == "ports"));
        assert!(report
            .fixes
            .iter()
            .any(|f| f.id == "existing_stack" && f.severity == "info"));
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["existing_stack"], true);
        assert_eq!(json["os"], "mac");
    }

    #[test]
    fn check_compose_v1_shim_is_not_v2_and_low_disk_warns() {
        let dir = tempfile::tempdir().unwrap();
        let runner = FakeRunner::new();
        runner.respond("docker --version", 0, "Docker version 20.10.0\n");
        runner.respond("docker info", 0, "20.10.0\n");
        runner.respond(
            "docker compose version",
            0,
            "docker-compose version 1.29.2, build x\n",
        );
        let mut pf = preflight(&runner, dir.path(), &[]);
        pf.disk_free_gb = Box::new(|| 3.2);
        let report = pf.check();
        assert!(!report.compose_v2 && !report.ready);
        let ids: Vec<&str> = report.fixes.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ids, vec!["compose_v2", "disk"]);
    }

    #[test]
    fn port_fix_wording() {
        let mut p = PortReport {
            port: 3000,
            service: "web app".into(),
            free: false,
            holder: None,
            docker: false,
            ours: false,
        };
        assert!(port_fix_text(&p, false).contains("in use by another app"));
        p.holder = Some("node (pid 9)".into());
        assert!(port_fix_text(&p, false).contains("Quit it before installing"));
        p.holder = Some("Docker Desktop (pid 1)".into());
        p.docker = true;
        assert!(port_fix_text(&p, true).contains("probably the other Crawler AI copy"));
    }

    #[cfg(unix)]
    fn sh(script: &str) -> Vec<String> {
        vec!["/bin/sh".into(), "-c".into(), script.into()]
    }

    fn real_runner() -> SystemRunner {
        let mut env = BTreeMap::new();
        env.insert("PATH".to_string(), "/usr/bin:/bin".to_string());
        env.insert("ONLY_THIS".to_string(), "yes".to_string());
        SystemRunner::new(Os::current(), env)
    }

    #[cfg(unix)]
    #[test]
    fn system_runner_captures_output_with_a_clean_env() {
        let runner = real_runner();
        let out = runner.run(
            &sh("echo out; echo err >&2; echo \"$ONLY_THIS-${HOME:-nohome}\"; exit 3"),
            None,
            Duration::from_secs(10),
        );
        assert_eq!(out.code, Some(3));
        assert_eq!(out.error, None);
        assert_eq!(out.stdout, "out\nyes-nohome\n");
        assert_eq!(out.stderr, "err\n");
        assert!(!out.ok());
        assert_eq!(out.describe_failure(), "exit code 3");
    }

    #[cfg(unix)]
    #[test]
    fn system_runner_streams_lines_in_cwd() {
        let dir = tempfile::tempdir().unwrap();
        let runner = real_runner();
        let mut lines = Vec::new();
        let cancel = AtomicBool::new(false);
        let out = runner.stream(
            &sh("pwd; printf 'a\\r\\nb'"),
            Some(dir.path()),
            Duration::from_secs(10),
            &cancel,
            &mut |l| lines.push(l.to_string()),
        );
        assert!(out.ok());
        let pwd = std::fs::canonicalize(dir.path()).unwrap();
        assert_eq!(
            std::fs::canonicalize(&lines[0]).unwrap(),
            pwd,
            "ran in the cwd"
        );
        assert_eq!(&lines[1..], &["a".to_string(), "b".to_string()]);
    }

    #[cfg(unix)]
    #[test]
    fn system_runner_times_out_and_cancels() {
        let runner = real_runner();
        let started = Instant::now();
        let out = runner.run(&sh("sleep 30"), None, Duration::from_millis(300));
        assert_eq!(out.error, Some(CmdError::Timeout));
        assert!(started.elapsed() < Duration::from_secs(10));

        let cancel = AtomicBool::new(true);
        let out = runner.stream(
            &sh("sleep 30"),
            None,
            Duration::from_secs(60),
            &cancel,
            &mut |_| {},
        );
        assert_eq!(out.error, Some(CmdError::Cancelled));
    }

    #[test]
    fn system_runner_reports_missing_programs() {
        let runner = real_runner();
        let out = runner.run(
            &["/definitely/not/here/docker".to_string()],
            None,
            Duration::from_secs(5),
        );
        assert_eq!(out.error, Some(CmdError::NotFound));
        assert_eq!(
            runner.run(&[], None, Duration::from_secs(1)).error,
            Some(CmdError::Io("empty command".into()))
        );
        assert_eq!(runner.which("definitely-not-a-program-xyz"), None);
    }
}

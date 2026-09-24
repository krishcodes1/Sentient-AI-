//! Step 3 of setup, "Install & start", and the tray's Start / Stop / Show logs: copy the
//! bundled Crawler AI source into this version's stack folder, run
//! `docker compose -p crawler-ai up --build -d` there, then poll the backend's health
//! endpoint until it answers.
//!
//! Why it exists: the app ships the exact source it builds (covered by its signature) and
//! drives the same Compose project name as the bootstrap, so every installer manages one
//! stack and its data volumes survive app updates. Phases
//! (idle -> copying -> building -> starting -> waiting -> healthy | failed) and log lines
//! are reported through a callback, which the Tauri layer turns into `stack://phase` and
//! `stack://log` events; tests drive it with a fake runner, probe and clock.

use std::collections::VecDeque;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::keys::env_key_status;
use crate::platform::{self, OwnerOnly, PathError};
use crate::preflight::{CmdError, CommandRunner};

/// Fixed so the app, the bootstrap and the CLI all manage one stack (and one set of
/// volumes); without it Compose would name the project after the folder ("docker").
pub const COMPOSE_PROJECT: &str = "crawler-ai";
pub const HEALTH_URL: &str = "http://127.0.0.1:8000/api/health";
pub const FRONTEND_URL: &str = "http://127.0.0.1:3000/";
/// What the Crawler AI window loads.
pub const APP_URL: &str = "http://localhost:3000";
const MAX_LINE_CHARS: usize = 4000;
const DIAGNOSE_TAIL: usize = 200;
const FAILURE_LOG_LINES: usize = 60;
pub const LOG_TAIL_LINES: usize = 200;

/// Top-level folders of the bundle that make up the stack.
const BUNDLE_DIRS: &[&str] = &["backend", "frontend", "docker"];
/// Never copied, at any depth: host caches, build output, VCS and agent state.
const SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "dist",
    "coverage",
    "htmlcov",
    ".claude",
];
/// Never copied, relative to the bundle root. docker/data is the old bind-mounted Postgres
/// folder (real user data in a developer checkout).
const SKIP_PATHS: &[&str] = &["backend/tests", "docker/data"];
/// Private keys and certificates with their keys (TLS, Apple signing, SSH).
const PRIVATE_KEY_EXTENSIONS: &[&str] = &["pem", "key", "p8", "p12", "pfx", "jks", "keystore"];
const SSH_KEY_NAMES: &[&str] = &["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    Idle,
    Copying,
    Building,
    Starting,
    Waiting,
    Healthy,
    Failed,
}

impl Phase {
    /// A job in this phase is still running.
    pub fn is_active(self) -> bool {
        matches!(
            self,
            Phase::Copying | Phase::Building | Phase::Starting | Phase::Waiting
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PhaseUpdate {
    pub phase: Phase,
    /// Set with `Failed`: what went wrong and what to do, in plain English.
    pub error: Option<String>,
    pub elapsed_s: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StackEvent {
    Log(String),
    Phase(PhaseUpdate),
}

// ── Seams for tests ──────────────────────────────────────────────────────────

pub trait HealthProbe: Send + Sync {
    /// True when `url` answers 2xx.
    fn ok(&self, url: &str) -> bool;
}

/// HTTP GET against the loopback stack; no proxy, no redirects, 5 s timeout.
pub struct HttpProbe {
    agent: ureq::Agent,
}

impl HttpProbe {
    pub fn new() -> Self {
        Self {
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(5))
                .redirects(0)
                .build(),
        }
    }
}

impl Default for HttpProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl HealthProbe for HttpProbe {
    fn ok(&self, url: &str) -> bool {
        match self.agent.get(url).call() {
            Ok(resp) => (200..300).contains(&resp.status()),
            Err(_) => false,
        }
    }
}

pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
    fn sleep(&self, duration: Duration);
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

#[derive(Debug, Clone)]
pub struct Timings {
    pub poll_interval: Duration,
    pub health_timeout: Duration,
    pub frontend_wait: Duration,
    pub build_timeout: Duration,
    /// `compose start` / `stop` / `logs`.
    pub command_timeout: Duration,
}

impl Default for Timings {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(3),
            health_timeout: Duration::from_secs(20 * 60),
            frontend_wait: Duration::from_secs(90),
            build_timeout: Duration::from_secs(2 * 60 * 60),
            command_timeout: Duration::from_secs(120),
        }
    }
}

// ── Layout ───────────────────────────────────────────────────────────────────

/// `<root>/<version>/{backend,frontend,docker}` for one app version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackLayout {
    pub root: PathBuf,
    pub version: String,
    pub dir: PathBuf,
}

impl StackLayout {
    pub fn new(root: PathBuf, version: &str) -> Result<Self, PathError> {
        let dir = platform::version_dir(&root, version)?;
        Ok(Self {
            root,
            version: version.to_string(),
            dir,
        })
    }

    pub fn docker_dir(&self) -> PathBuf {
        self.dir.join("docker")
    }
    pub fn compose_file(&self) -> PathBuf {
        self.docker_dir().join("docker-compose.yml")
    }
    pub fn backend_dir(&self) -> PathBuf {
        self.dir.join("backend")
    }
    pub fn env_file(&self) -> PathBuf {
        self.backend_dir().join(".env")
    }
}

/// A folder holding the stack source: docker/docker-compose.yml, backend/.env.example
/// and frontend/.
pub fn looks_like_bundle(dir: &Path) -> bool {
    dir.join("docker").join("docker-compose.yml").is_file()
        && dir.join("backend").join(".env.example").is_file()
        && dir.join("frontend").is_dir()
}

/// Same rules as scripts/stage-stack.mjs `isExcluded`: secrets (.env, its backups, foo.env,
/// private keys), local databases, caches and build state.
fn skip_file(name: &str) -> bool {
    let secret_env =
        name.ends_with(".env") || (name.starts_with(".env.") && name != ".env.example");
    let private_key = Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| {
            PRIVATE_KEY_EXTENSIONS
                .iter()
                .any(|k| k.eq_ignore_ascii_case(e))
        })
        || SSH_KEY_NAMES.contains(&name);
    secret_env
        || private_key
        || name.ends_with(".pyc")
        || name.ends_with(".db")
        || name == ".DS_Store"
        || name == ".coverage"
        || name == "tsconfig.tsbuildinfo"
        || name.starts_with("bootstrap.log")
}

fn copy_dir(src: &Path, dst: &Path, rel: &str, copied: &mut usize) -> io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let rel_child = format!("{rel}/{name}");
        // DirEntry::file_type does not follow links: they are skipped, never followed out
        // of the bundle.
        let kind = entry.file_type()?;
        if kind.is_dir() {
            if SKIP_DIRS.contains(&name.as_str()) || SKIP_PATHS.contains(&rel_child.as_str()) {
                continue;
            }
            copy_dir(&entry.path(), &dst.join(&name), &rel_child, copied)?;
        } else if kind.is_file() && !skip_file(&name) {
            fs::copy(entry.path(), dst.join(&name))?;
            *copied += 1;
        }
    }
    Ok(())
}

/// Copy the bundle's backend/, frontend/ and docker/ into `dst`, overwriting files it
/// ships and leaving everything else (backend/.env and its backups) alone. Secrets, caches
/// and tests are skipped, so a developer checkout can serve as the bundle in debug builds.
pub fn copy_bundle(src: &Path, dst: &Path) -> io::Result<usize> {
    let mut copied = 0;
    for dir in BUNDLE_DIRS {
        let from = src.join(dir);
        if from.is_dir() {
            copy_dir(&from, &dst.join(dir), dir, &mut copied)?;
        }
    }
    Ok(copied)
}

// ── Output handling ──────────────────────────────────────────────────────────

/// Drop ANSI CSI/OSC sequences and control characters (tab kept), like bootstrap.py.
pub fn strip_ansi(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\x1b' {
            if chars.get(i + 1) == Some(&'[') {
                let mut j = i + 2;
                while j < chars.len()
                    && (chars[j].is_ascii_digit() || chars[j] == ';' || chars[j] == '?')
                {
                    j += 1;
                }
                while j < chars.len() && (' '..='/').contains(&chars[j]) {
                    j += 1;
                }
                if j < chars.len() && ('@'..='~').contains(&chars[j]) {
                    i = j + 1;
                    continue;
                }
            } else if chars.get(i + 1) == Some(&']') {
                let mut j = i + 2;
                while j < chars.len() && chars[j] != '\x07' && chars[j] != '\x1b' {
                    j += 1;
                }
                if j < chars.len() && chars[j] == '\x07' {
                    i = j + 1;
                    continue;
                }
                if j + 1 < chars.len() && chars[j] == '\x1b' && chars[j + 1] == '\\' {
                    i = j + 2;
                    continue;
                }
            }
        }
        let control = (c <= '\x08') || ('\x0b'..='\x1f').contains(&c) || c == '\x7f';
        if !control {
            out.push(c);
        }
        i += 1;
    }
    out
}

/// One display line: the final state of a `\r` progress redraw, no escapes, capped.
pub fn clean_line(raw: &str) -> String {
    let text = raw.trim_end_matches('\n');
    let text = if text.contains('\r') {
        text.split('\r')
            .rev()
            .find(|seg| !seg.trim().is_empty())
            .unwrap_or("")
    } else {
        text
    };
    strip_ansi(&text.replace('\n', " "))
        .chars()
        .take(MAX_LINE_CHARS)
        .collect()
}

/// Compose's " Container crawler-ai-db-1  Started" style progress lines.
fn is_container_line(line: &str) -> bool {
    const STATES: &[&str] = &["creat", "recreat", "start", "running", "waiting", "healthy"];
    let tokens: Vec<&str> = line.split_whitespace().collect();
    tokens.windows(3).any(|w| {
        let first = w[0].to_ascii_lowercase();
        let boundary = first.len() == 9
            || first
                .chars()
                .rev()
                .nth(9)
                .is_some_and(|c| !(c.is_alphanumeric() || c == '_'));
        first.ends_with("container")
            && boundary
            && STATES
                .iter()
                .any(|s| w[2].to_ascii_lowercase().starts_with(s))
    })
}

/// The hint for one lower-cased compose output line, if it shows a known failure.
fn diagnose_line(l: &str) -> Option<&'static str> {
    let any = |needles: &[&str]| needles.iter().any(|n| l.contains(n));
    let then = |first: &str, second: &str| l.find(first).is_some_and(|i| l[i..].contains(second));
    if any(&[
        "cannot connect to the docker daemon",
        "is the docker daemon running",
        "docker daemon is not running",
        "dockerdesktoplinuxengine",
    ]) || then("docker_engine", "cannot find")
    {
        return Some("Docker Desktop isn't running. Open it, wait for Running, then click Retry.");
    }
    if any(&[
        "port is already allocated",
        "address already in use",
        "ports are not available",
    ]) {
        return Some(
            "A port Crawler AI needs (3000, 8000, 5432 or 6379) is taken by another app. Quit it, \
             then click Retry.",
        );
    }
    if l.contains("no space left on device") {
        return Some(
            "Docker ran out of disk space. Free some in Docker Desktop (Settings > Resources, or \
             Troubleshoot > Clean / Purge data), then click Retry.",
        );
    }
    if then("env file", "not found") || l.contains(".env: no such file") {
        return Some("backend/.env is missing. Go back to step 2 and save the keys.");
    }
    if any(&[
        "tls handshake timeout",
        "i/o timeout",
        "temporary failure in name resolution",
        "no such host",
        "connection reset by peer",
        "unexpected eof",
    ]) {
        return Some(
            "Docker couldn't finish downloading. Check your internet connection, then click Retry.",
        );
    }
    None
}

/// A plain-English hint for the most common compose failures (bootstrap.py's diagnose):
/// the last of the final 200 lines that shows a known failure decides.
pub fn diagnose<'a>(lines: impl DoubleEndedIterator<Item = &'a String>) -> Option<&'static str> {
    lines
        .rev()
        .take(DIAGNOSE_TAIL)
        .find_map(|line| diagnose_line(&line.to_lowercase()))
}

// ── The stack ────────────────────────────────────────────────────────────────

struct Job<'a> {
    emit: &'a mut dyn FnMut(StackEvent),
    clock: &'a dyn Clock,
    started: Instant,
}

impl Job<'_> {
    fn elapsed(&self) -> u64 {
        self.clock
            .now()
            .saturating_duration_since(self.started)
            .as_secs()
    }

    fn phase(&mut self, phase: Phase) {
        let update = PhaseUpdate {
            phase,
            error: None,
            elapsed_s: self.elapsed(),
        };
        (self.emit)(StackEvent::Phase(update));
    }

    fn log(&mut self, line: impl Into<String>) {
        (self.emit)(StackEvent::Log(line.into()));
    }

    fn fail(&mut self, message: impl Into<String>) -> Result<(), String> {
        let message = message.into();
        let update = PhaseUpdate {
            phase: Phase::Failed,
            error: Some(message.clone()),
            elapsed_s: self.elapsed(),
        };
        (self.emit)(StackEvent::Phase(update));
        Err(message)
    }
}

pub struct Stack {
    pub layout: StackLayout,
    /// The bundled source (`<resources>/stack`), when the app has one.
    pub bundle: Option<PathBuf>,
    pub timings: Timings,
    pub health_url: String,
    pub frontend_url: String,
    runner: Arc<dyn CommandRunner>,
    probe: Arc<dyn HealthProbe>,
    clock: Arc<dyn Clock>,
    perms: OwnerOnly,
    cancel: AtomicBool,
}

impl Stack {
    pub fn new(
        layout: StackLayout,
        bundle: Option<PathBuf>,
        runner: Arc<dyn CommandRunner>,
        probe: Arc<dyn HealthProbe>,
        clock: Arc<dyn Clock>,
        perms: OwnerOnly,
    ) -> Self {
        Self {
            layout,
            bundle,
            timings: Timings::default(),
            health_url: HEALTH_URL.into(),
            frontend_url: FRONTEND_URL.into(),
            runner,
            probe,
            clock,
            perms,
            cancel: AtomicBool::new(false),
        }
    }

    /// Ask a running install/start to stop at the next opportunity (kills compose).
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::SeqCst);
    }

    fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::SeqCst)
    }

    fn compose_argv(&self, docker: &Path, rest: &[&str]) -> Vec<String> {
        let mut argv = vec![
            docker.to_string_lossy().into_owned(),
            "compose".into(),
            "-p".into(),
            COMPOSE_PROJECT.into(),
        ];
        argv.extend(rest.iter().map(|s| s.to_string()));
        argv
    }

    fn docker(&self) -> Result<PathBuf, String> {
        self.runner.which("docker").ok_or_else(|| {
            "Docker isn't installed or couldn't be found. Install Docker Desktop, then click Retry."
                .to_string()
        })
    }

    /// The stack for this version has been copied and has its keys.
    pub fn is_installed(&self) -> bool {
        self.layout.compose_file().is_file() && env_key_status(&self.layout.env_file()).all_set()
    }

    pub fn backend_healthy(&self) -> bool {
        self.probe.ok(&self.health_url)
    }

    /// When this version has no backend/.env yet but an earlier version's stack folder
    /// has one with real keys, copy it (owner-only): new keys would make the data already
    /// in the shared database volume unreadable. Returns the version it came from.
    pub fn adopt_previous_env(&self) -> io::Result<Option<String>> {
        let target = self.layout.env_file();
        if target.exists() {
            return Ok(None);
        }
        let Ok(entries) = fs::read_dir(&self.layout.root) else {
            return Ok(None);
        };
        let mut best: Option<(SystemTime, String, PathBuf)> = None;
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == self.layout.version
                || platform::version_dir(&self.layout.root, &name).is_err()
            {
                continue;
            }
            let candidate = entry.path().join("backend").join(".env");
            let Ok(meta) = fs::symlink_metadata(&candidate) else {
                continue;
            };
            if !meta.is_file() || !env_key_status(&candidate).all_set() {
                continue;
            }
            let modified = meta.modified().unwrap_or(UNIX_EPOCH);
            if best.as_ref().is_none_or(|(when, _, _)| modified > *when) {
                best = Some((modified, name, candidate));
            }
        }
        let Some((_, version, source)) = best else {
            return Ok(None);
        };
        let data = fs::read(&source)?;
        if let Some(dir) = target.parent() {
            fs::create_dir_all(dir)?;
        }
        match self.perms.create_new(&target, &data) {
            Ok(()) => Ok(Some(version)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// copying -> building -> starting -> waiting -> healthy | failed. Returns the
    /// failure message (also sent as the `Failed` phase's error).
    pub fn install(&self, emit: &mut dyn FnMut(StackEvent)) -> Result<(), String> {
        self.cancel.store(false, Ordering::SeqCst);
        let mut job = Job {
            emit,
            clock: self.clock.as_ref(),
            started: self.clock.now(),
        };

        job.phase(Phase::Copying);
        let Some(bundle) = self.bundle.as_deref().filter(|b| looks_like_bundle(b)) else {
            return job.fail(
                "This app's copy of Crawler AI is missing or damaged. Reinstall the app, then \
                 click Retry.",
            );
        };
        job.log(format!(
            "Copying Crawler AI {} to {}",
            self.layout.version,
            self.layout.dir.display()
        ));
        match copy_bundle(bundle, &self.layout.dir) {
            Ok(count) => job.log(format!("Copied {count} files.")),
            Err(err) => return job.fail(format!("Couldn't copy Crawler AI's files ({err}).")),
        }
        match self.adopt_previous_env() {
            Ok(Some(version)) => {
                job.log(format!("Kept your security keys from version {version}."))
            }
            Ok(None) => {}
            Err(err) => job.log(format!(
                "Couldn't carry over the earlier version's keys ({err})."
            )),
        }
        if !env_key_status(&self.layout.env_file()).all_set() {
            return job.fail("Save your security keys first (step 2), then click Retry.");
        }
        let docker = match self.docker() {
            Ok(path) => path,
            Err(message) => return job.fail(message),
        };

        job.phase(Phase::Building);
        job.log(format!(
            "$ docker compose -p {COMPOSE_PROJECT} up --build -d"
        ));
        let argv = self.compose_argv(&docker, &["up", "--build", "-d"]);
        let mut tail: VecDeque<String> = VecDeque::with_capacity(DIAGNOSE_TAIL);
        let mut saw_containers = false;
        let out = self.runner.stream(
            &argv,
            Some(&self.layout.docker_dir()),
            self.timings.build_timeout,
            &self.cancel,
            &mut |raw| {
                let line = clean_line(raw);
                if !saw_containers && is_container_line(&line) {
                    saw_containers = true;
                    job.phase(Phase::Starting);
                }
                if tail.len() == DIAGNOSE_TAIL {
                    tail.pop_front();
                }
                tail.push_back(line.clone());
                job.log(line);
            },
        );
        match out.error {
            Some(CmdError::Cancelled) => return job.fail("Stopped before the install finished."),
            Some(CmdError::Timeout) => {
                return job.fail(format!(
                    "The build took longer than {} minutes and was stopped. Check your internet \
                     connection, then click Retry.",
                    self.timings.build_timeout.as_secs() / 60
                ))
            }
            Some(CmdError::NotFound) => {
                return job.fail(
                    "Docker couldn't be started. Reinstall Docker Desktop, then click Retry.",
                )
            }
            Some(CmdError::Io(reason)) => {
                return job.fail(format!("Couldn't start Docker Compose ({reason})."))
            }
            None => {}
        }
        if out.code != Some(0) {
            let code = out
                .code
                .map_or_else(|| "a signal".to_string(), |c| format!("exit code {c}"));
            let hint = diagnose(tail.iter()).unwrap_or("The log above says why.");
            return job.fail(format!("Docker Compose stopped with {code}. {hint}"));
        }
        if !saw_containers {
            job.phase(Phase::Starting);
        }
        self.wait_healthy(&mut job, &docker)
    }

    /// `docker compose start` for an installed stack, then wait for health:
    /// starting -> waiting -> healthy | failed.
    pub fn start(&self, emit: &mut dyn FnMut(StackEvent)) -> Result<(), String> {
        self.cancel.store(false, Ordering::SeqCst);
        let mut job = Job {
            emit,
            clock: self.clock.as_ref(),
            started: self.clock.now(),
        };
        job.phase(Phase::Starting);
        if !self.layout.compose_file().is_file() {
            return job.fail("Crawler AI isn't installed yet. Run Install & start first.");
        }
        let docker = match self.docker() {
            Ok(path) => path,
            Err(message) => return job.fail(message),
        };
        job.log(format!("$ docker compose -p {COMPOSE_PROJECT} start"));
        let argv = self.compose_argv(&docker, &["start"]);
        let mut tail: Vec<String> = Vec::new();
        let out = self.runner.stream(
            &argv,
            Some(&self.layout.docker_dir()),
            self.timings.command_timeout,
            &self.cancel,
            &mut |raw| {
                let line = clean_line(raw);
                tail.push(line.clone());
                job.log(line);
            },
        );
        if !out.ok() {
            let hint = diagnose(tail.iter())
                .unwrap_or("If it was never built, run Install & start instead.");
            return job.fail(format!(
                "Docker Compose couldn't start Crawler AI ({}). {hint}",
                out.describe_failure()
            ));
        }
        self.wait_healthy(&mut job, &docker)
    }

    fn wait_healthy(&self, job: &mut Job<'_>, docker: &Path) -> Result<(), String> {
        job.phase(Phase::Waiting);
        job.log(format!(
            "Waiting for the backend at {} ...",
            self.health_url
        ));
        let deadline = self.clock.now() + self.timings.health_timeout;
        while !self.probe.ok(&self.health_url) {
            if self.cancelled() {
                return job.fail("Stopped before the backend came up.");
            }
            if self.clock.now() >= deadline {
                job.log("----- last backend log lines -----");
                let lines = self.logs_with(docker, FAILURE_LOG_LINES);
                for line in lines {
                    job.log(line);
                }
                return job.fail(format!(
                    "The containers started, but the backend didn't answer within {} minutes. \
                     The backend's last log lines are above.",
                    self.timings.health_timeout.as_secs() / 60
                ));
            }
            self.clock.sleep(self.timings.poll_interval);
        }
        job.log("Backend is healthy.");

        let deadline = self.clock.now() + self.timings.frontend_wait;
        let mut up = self.probe.ok(&self.frontend_url);
        while !up && self.clock.now() < deadline && !self.cancelled() {
            self.clock
                .sleep(self.timings.poll_interval.min(Duration::from_secs(2)));
            up = self.probe.ok(&self.frontend_url);
        }
        job.log(if up {
            "Web app is answering on port 3000."
        } else {
            "The web app on port 3000 is still starting; give it a minute if the page is blank."
        });
        job.phase(Phase::Healthy);
        Ok(())
    }

    /// `docker compose stop` (containers and data are kept).
    pub fn stop(&self) -> Result<(), String> {
        let docker = self.docker()?;
        let cwd = self.layout.docker_dir();
        let cwd = cwd.is_dir().then_some(cwd);
        let out = self.runner.run(
            &self.compose_argv(&docker, &["stop"]),
            cwd.as_deref(),
            self.timings.command_timeout,
        );
        if out.ok() {
            Ok(())
        } else {
            let lines: Vec<String> = out.stderr.lines().map(clean_line).collect();
            let hint = diagnose(lines.iter()).unwrap_or("");
            Err(format!(
                "Docker Compose couldn't stop Crawler AI ({}). {hint}",
                out.describe_failure()
            )
            .trim_end()
            .to_string())
        }
    }

    /// The backend's last `LOG_TAIL_LINES` log lines.
    pub fn logs(&self) -> Result<Vec<String>, String> {
        let docker = self.docker()?;
        Ok(self.logs_with(&docker, LOG_TAIL_LINES))
    }

    fn logs_with(&self, docker: &Path, lines: usize) -> Vec<String> {
        let cwd = self.layout.docker_dir();
        let cwd = cwd.is_dir().then_some(cwd);
        let count = lines.to_string();
        let argv = self.compose_argv(docker, &["logs", "--no-color", "--tail", &count, "backend"]);
        let out = self
            .runner
            .run(&argv, cwd.as_deref(), Duration::from_secs(30));
        let mut all: Vec<String> = out
            .stdout
            .lines()
            .chain(out.stderr.lines())
            .map(clean_line)
            .collect();
        if all.len() > lines {
            all.drain(..all.len() - lines);
        }
        all
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{
        owner_only, runner_with_account, FakeClock, FakeRunner, ScriptedProbe,
    };

    fn good_env() -> String {
        format!(
            "SECRET_KEY={}\nENCRYPTION_KEY={}\n",
            crate::keys::generate_secret_key().unwrap(),
            crate::keys::generate_encryption_key().unwrap()
        )
    }

    fn make_bundle(dir: &Path) -> PathBuf {
        let bundle = dir.join("bundle");
        for (path, body) in [
            ("docker/docker-compose.yml", "services: {}\n"),
            ("backend/.env.example", "SECRET_KEY=REPLACE_ME\n"),
            ("backend/main.py", "print('hi')\n"),
            ("backend/.env", "SECRET_KEY=must-never-be-copied\n"),
            ("backend/.env.local", "X=1\n"),
            ("backend/tests/test_x.py", "\n"),
            ("backend/core/__pycache__/x.pyc", "\n"),
            ("frontend/package.json", "{}\n"),
            ("frontend/node_modules/left-pad/index.js", "\n"),
            ("frontend/src/App.tsx", "\n"),
            ("installer/bootstrap.py", "\n"),
        ] {
            let full = bundle.join(path);
            fs::create_dir_all(full.parent().unwrap()).unwrap();
            fs::write(full, body).unwrap();
        }
        bundle
    }

    struct Rig {
        _dir: tempfile::TempDir,
        runner: Arc<FakeRunner>,
        probe: Arc<ScriptedProbe>,
        clock: Arc<FakeClock>,
        stack: Stack,
    }

    fn rig(with_keys: bool) -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let bundle = make_bundle(dir.path());
        let layout = StackLayout::new(dir.path().join("stack"), "1.0.0").unwrap();
        if with_keys {
            fs::create_dir_all(layout.backend_dir()).unwrap();
            fs::write(layout.env_file(), good_env()).unwrap();
        }
        let runner = runner_with_account();
        let probe = Arc::new(ScriptedProbe::default());
        let clock = Arc::new(FakeClock::new());
        let perms = owner_only(runner.clone());
        let stack = Stack::new(
            layout,
            Some(bundle),
            runner.clone(),
            probe.clone(),
            clock.clone(),
            perms,
        );
        Rig {
            _dir: dir,
            runner,
            probe,
            clock,
            stack,
        }
    }

    fn run_install(stack: &Stack) -> (Result<(), String>, Vec<Phase>, Vec<String>) {
        let mut phases = Vec::new();
        let mut logs = Vec::new();
        let result = stack.install(&mut |event| match event {
            StackEvent::Phase(update) => phases.push(update.phase),
            StackEvent::Log(line) => logs.push(line),
        });
        (result, phases, logs)
    }

    #[test]
    fn install_success_walks_every_phase() {
        let rig = rig(true);
        rig.runner.stream_lines(
            "up --build -d",
            0,
            &[
                "#1 [backend internal] load build definition",
                "\x1b[32m#2 DONE 0.1s\x1b[0m",
                " Container crawler-ai-db-1  Creating",
                " Container crawler-ai-db-1  Started",
            ],
        );
        rig.probe.set("http://127.0.0.1:8000/api/health", 3);
        rig.probe.set("http://127.0.0.1:3000/", 1);
        let (result, phases, logs) = run_install(&rig.stack);
        assert_eq!(result, Ok(()));
        assert_eq!(
            phases,
            vec![
                Phase::Copying,
                Phase::Building,
                Phase::Starting,
                Phase::Waiting,
                Phase::Healthy
            ]
        );
        assert!(logs.contains(&"#2 DONE 0.1s".to_string()), "ANSI stripped");
        assert!(logs.contains(&"Backend is healthy.".to_string()));
        assert!(logs.contains(&"Web app is answering on port 3000.".to_string()));

        // Compose ran in the copied docker/ folder with the fixed project name.
        let stream = rig.runner.streamed();
        assert_eq!(
            &stream[0].0[1..],
            &["compose", "-p", "crawler-ai", "up", "--build", "-d"]
        );
        assert_eq!(
            stream[0].1.as_deref(),
            Some(rig.stack.layout.docker_dir().as_path())
        );

        // The copy skipped secrets, caches, tests and anything outside the three folders.
        let dir = &rig.stack.layout.dir;
        assert!(dir.join("docker/docker-compose.yml").is_file());
        assert!(dir.join("backend/main.py").is_file());
        assert!(dir.join("frontend/src/App.tsx").is_file());
        assert!(!dir.join("backend/.env.local").exists());
        assert!(!dir.join("backend/tests").exists());
        assert!(!dir.join("backend/core/__pycache__").exists());
        assert!(!dir.join("frontend/node_modules").exists());
        assert!(!dir.join("installer").exists());
        let env = fs::read_to_string(rig.stack.layout.env_file()).unwrap();
        assert!(
            !env.contains("must-never-be-copied"),
            "the bundle's .env never lands"
        );
        // Health was polled every 3 s on the fake clock.
        assert!(rig.clock.slept() >= Duration::from_secs(6));
    }

    /// Same rules as scripts/stage-stack.mjs: a developer checkout used as the bundle in
    /// debug builds must never leak keys, key backups, private keys or local database files.
    #[test]
    fn copy_bundle_never_copies_secrets_or_local_data() {
        let dir = tempfile::tempdir().unwrap();
        let bundle = make_bundle(dir.path());
        for path in [
            "backend/.env.bak-20260924-181500",
            "backend/prod.env",
            "backend/certs/server.pem",
            "backend/certs/server.key",
            "backend/certs/client.p12",
            "backend/certs/client.pfx",
            "backend/AuthKey_ABC123.p8",
            "backend/id_rsa",
            "backend/id_ed25519",
            "backend/dev_verify.db",
            "docker/data/pg/PG_VERSION",
        ] {
            let full = bundle.join(path);
            fs::create_dir_all(full.parent().unwrap()).unwrap();
            fs::write(full, "secret\n").unwrap();
        }
        fs::create_dir_all(bundle.join("backend/services/data")).unwrap();
        fs::write(bundle.join("backend/services/data/schema.py"), "\n").unwrap();
        let dst = dir.path().join("out");
        copy_bundle(&bundle, &dst).unwrap();

        for gone in [
            "backend/.env",
            "backend/.env.local",
            "backend/.env.bak-20260924-181500",
            "backend/prod.env",
            "backend/certs/server.pem",
            "backend/certs/server.key",
            "backend/certs/client.p12",
            "backend/certs/client.pfx",
            "backend/AuthKey_ABC123.p8",
            "backend/id_rsa",
            "backend/id_ed25519",
            "backend/dev_verify.db",
            "docker/data",
        ] {
            assert!(!dst.join(gone).exists(), "copied {gone}");
        }
        for kept in [
            "backend/.env.example",
            "backend/main.py",
            "backend/services/data/schema.py",
            "docker/docker-compose.yml",
        ] {
            assert!(dst.join(kept).is_file(), "missing {kept}");
        }
    }

    #[test]
    fn install_compose_failure_reports_hint() {
        let rig = rig(true);
        rig.runner.stream_lines(
            "up --build -d",
            1,
            &["Error response from daemon: Ports are not available: listen tcp 0.0.0.0:5432: bind: address already in use"],
        );
        let (result, phases, _) = run_install(&rig.stack);
        let message = result.unwrap_err();
        assert!(message.starts_with("Docker Compose stopped with exit code 1."));
        assert!(message.contains("port Crawler AI needs"));
        assert_eq!(phases.last(), Some(&Phase::Failed));
        assert!(!phases.contains(&Phase::Waiting));
    }

    #[test]
    fn install_health_timeout_dumps_backend_logs() {
        let rig = rig(true);
        rig.runner.stream_lines(
            "up --build -d",
            0,
            &[" Container crawler-ai-backend-1  Started"],
        );
        rig.runner.respond(
            "logs --no-color --tail 60 backend",
            0,
            "Traceback\nValueError: boom\n",
        );
        let (result, phases, logs) = run_install(&rig.stack);
        let message = result.unwrap_err();
        assert!(message.contains("didn't answer within 20 minutes"));
        assert_eq!(phases.last(), Some(&Phase::Failed));
        assert!(phases.contains(&Phase::Waiting));
        assert!(logs.contains(&"ValueError: boom".to_string()));
        assert!(rig.clock.slept() >= Duration::from_secs(20 * 60));
    }

    #[test]
    fn install_needs_keys_bundle_and_docker() {
        let rig_no_keys = rig(false);
        let (result, phases, _) = run_install(&rig_no_keys.stack);
        assert!(result.unwrap_err().contains("step 2"));
        assert_eq!(phases, vec![Phase::Copying, Phase::Failed]);
        assert!(rig_no_keys.runner.streamed().is_empty());

        let mut rig_no_bundle = rig(true);
        rig_no_bundle.stack.bundle = None;
        assert!(run_install(&rig_no_bundle.stack)
            .0
            .unwrap_err()
            .contains("Reinstall the app"));

        let rig_no_docker = rig(true);
        rig_no_docker.runner.missing("docker");
        assert!(run_install(&rig_no_docker.stack)
            .0
            .unwrap_err()
            .contains("Install Docker Desktop"));
    }

    #[test]
    fn install_timeout_and_cancel() {
        let rig = rig(true);
        rig.runner.stream_error("up --build -d", CmdError::Timeout);
        assert!(run_install(&rig.stack)
            .0
            .unwrap_err()
            .contains("longer than 120 minutes"));
        let rig = rig_cancelled();
        assert_eq!(
            run_install(&rig.stack).0.unwrap_err(),
            "Stopped before the install finished."
        );
    }

    fn rig_cancelled() -> Rig {
        let rig = rig(true);
        rig.runner
            .stream_error("up --build -d", CmdError::Cancelled);
        rig
    }

    #[test]
    fn adopts_keys_from_an_earlier_version() {
        let rig = rig(false);
        let old = rig.stack.layout.root.join("0.9.0").join("backend");
        fs::create_dir_all(&old).unwrap();
        let env = good_env();
        fs::write(old.join(".env"), &env).unwrap();
        // A newer-looking folder without real keys is ignored.
        let junk = rig.stack.layout.root.join("0.9.5").join("backend");
        fs::create_dir_all(&junk).unwrap();
        fs::write(junk.join(".env"), "SECRET_KEY=changeme\n").unwrap();
        assert_eq!(
            rig.stack.adopt_previous_env().unwrap().as_deref(),
            Some("0.9.0")
        );
        assert_eq!(
            fs::read_to_string(rig.stack.layout.env_file()).unwrap(),
            env
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(rig.stack.layout.env_file())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // Already has one: nothing to do.
        assert_eq!(rig.stack.adopt_previous_env().unwrap(), None);
    }

    #[test]
    fn start_stop_logs() {
        let rig = rig(true);
        copy_bundle(rig.stack.bundle.as_deref().unwrap(), &rig.stack.layout.dir).unwrap();
        rig.probe.set(HEALTH_URL, 0);
        rig.probe.set(FRONTEND_URL, 0);
        let mut phases = Vec::new();
        rig.stack
            .start(&mut |e| {
                if let StackEvent::Phase(p) = e {
                    phases.push(p.phase)
                }
            })
            .unwrap();
        assert_eq!(
            phases,
            vec![Phase::Starting, Phase::Waiting, Phase::Healthy]
        );
        assert_eq!(
            &rig.runner.streamed()[0].0[1..],
            &["compose", "-p", "crawler-ai", "start"]
        );

        rig.stack.stop().unwrap();
        rig.runner.respond(
            "logs --no-color --tail 200 backend",
            0,
            "a\n\x1b[31mb\x1b[0m\n",
        );
        assert_eq!(
            rig.stack.logs().unwrap(),
            vec!["a".to_string(), "b".to_string()]
        );
        let calls = rig.runner.calls();
        assert!(calls
            .iter()
            .any(|c| c[1..] == ["compose", "-p", "crawler-ai", "stop"]));

        rig.runner.respond("compose -p crawler-ai stop", 1, "");
        assert!(rig.stack.stop().unwrap_err().contains("couldn't stop"));
    }

    #[test]
    fn start_before_install_fails() {
        let rig = rig(true);
        let result = rig.stack.start(&mut |_| {});
        assert!(result.unwrap_err().contains("isn't installed yet"));
    }

    #[test]
    fn line_cleaning() {
        assert_eq!(clean_line("50%\r75%\r100%\n"), "100%");
        assert_eq!(clean_line("a\x1b[1;32mgreen\x1b[0m b"), "agreen b");
        assert_eq!(clean_line("\x1b]0;title\x07after"), "after");
        assert_eq!(clean_line("tab\there\x00\x7f"), "tab\there");
        assert_eq!(clean_line(&"x".repeat(5000)).len(), MAX_LINE_CHARS);
        assert!(is_container_line(" Container crawler-ai-db-1  Started"));
        assert!(is_container_line("container x recreated"));
        assert!(!is_container_line("MyContainer x Started"));
        assert!(!is_container_line("#5 [backend 2/6] RUN pip install"));
    }

    #[test]
    fn diagnose_hints() {
        let lines = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let hint = |v: &[&str]| diagnose(lines(v).iter());
        assert!(hint(&["Cannot connect to the Docker daemon at unix:///x"])
            .unwrap()
            .contains("isn't running"));
        assert!(hint(&["write /var/lib: no space left on device"])
            .unwrap()
            .contains("disk space"));
        assert!(hint(&["env file /x/backend/.env not found: stat"])
            .unwrap()
            .contains("step 2"));
        assert!(hint(&["net/http: TLS handshake timeout"])
            .unwrap()
            .contains("internet"));
        assert_eq!(hint(&["all fine"]), None);
        // The last matching line wins.
        assert!(
            hint(&["no space left on device", "port is already allocated"])
                .unwrap()
                .contains("port")
        );
    }

    #[test]
    fn layout_paths() {
        let layout = StackLayout::new(PathBuf::from("/r/stack"), "1.2.3").unwrap();
        assert_eq!(layout.dir, PathBuf::from("/r/stack/1.2.3"));
        assert_eq!(
            layout.compose_file(),
            PathBuf::from("/r/stack/1.2.3/docker/docker-compose.yml")
        );
        assert_eq!(
            layout.env_file(),
            PathBuf::from("/r/stack/1.2.3/backend/.env")
        );
        assert!(StackLayout::new(PathBuf::from("/r"), "../x").is_err());
    }

    /// One-shot HTTP server on an ephemeral loopback port answering with `status`.
    fn serve_once(status: &'static str) -> String {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/api/health", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            if let Ok((mut conn, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = conn.read(&mut buf);
                let body = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                );
                let _ = conn.write_all(body.as_bytes());
            }
        });
        url
    }

    #[test]
    fn http_probe_needs_a_2xx() {
        let _net = crate::test_support::net_lock();
        let probe = HttpProbe::new();
        assert!(probe.ok(&serve_once("200 OK")));
        assert!(!probe.ok(&serve_once("500 Internal Server Error")));
        assert!(!probe.ok(&serve_once("302 Found")));
        let closed = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            format!("http://{}/", l.local_addr().unwrap())
        };
        assert!(!probe.ok(&closed));
    }
}

//! The IPC surface of the setup window: `#[tauri::command]` wrappers around preflight,
//! keys and stack, the `stack://log` / `stack://phase` events, and the hooks the tray and
//! the windows use (`is_installed`, start/stop in the background).
//!
//! Why it exists: it is the only core file that knows about Tauri, so the other modules
//! stay testable without a UI build. `register()` is the one hook main.rs calls. The command
//! names and payloads are the setup UI's contract (desktop/ui/src/bridge.ts): change them
//! there and here together. build.rs derives the app ACL from the `#[tauri::command]`
//! functions in this file, and capabilities/setup.json grants that set to the "setup"
//! window only, so the Crawler AI window (http://localhost:3000) can call none of them.
//!
//! Payloads are snake_case JSON, arguments too (`rename_all = "snake_case"`).

use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, Runtime};

use crate::keys::{KeyMode, KeyWriter, WriteReport};
use crate::platform::{self, Os, OwnerOnly};
use crate::preflight::{CommandRunner, Preflight, PreflightReport, SystemRunner};
use crate::stack::{
    looks_like_bundle, HttpProbe, Phase, Stack, StackEvent, StackLayout, SystemClock,
};
use crate::updates::{self, UpdateInfo};
use crate::windows::{self, SETUP_WINDOW};

pub const EVENT_LOG: &str = "stack://log";
pub const EVENT_PHASE: &str = "stack://phase";
const MAX_JOB_LINES: usize = 2000;
/// How long Stop waits for a cancelled install/start to wind down before `compose stop`.
const CANCEL_WAIT: Duration = Duration::from_secs(15);

// ── Core (Tauri-free) ────────────────────────────────────────────────────────

/// Everything the commands act on, built once per app run.
pub struct Core {
    pub os: Os,
    pub version: String,
    pub stack_root: PathBuf,
    pub env: BTreeMap<String, String>,
    pub runner: Arc<dyn CommandRunner>,
    pub stack: Stack,
    pub keys: KeyWriter,
}

impl Core {
    /// Real runner/probe/clock, the per-user stack root, and the bundle found next to
    /// the app's resources.
    pub fn new(version: &str, resource_dir: Option<PathBuf>) -> Result<Self, String> {
        let os = Os::current();
        let root = platform::default_stack_root().map_err(|e| e.to_string())?;
        let system = SystemRunner::for_this_process();
        let env = system.env().clone();
        let runner: Arc<dyn CommandRunner> = Arc::new(system);
        Self::from_parts(os, version, root, find_bundle(resource_dir), env, runner)
    }

    pub fn from_parts(
        os: Os,
        version: &str,
        stack_root: PathBuf,
        bundle: Option<PathBuf>,
        env: BTreeMap<String, String>,
        runner: Arc<dyn CommandRunner>,
    ) -> Result<Self, String> {
        let layout = StackLayout::new(stack_root.clone(), version).map_err(|e| e.to_string())?;
        let perms = OwnerOnly::new(os, runner.clone(), env.clone());
        // Before the first install copies the bundle, the template is read from it.
        let example = bundle
            .as_ref()
            .map(|b| b.join("backend").join(".env.example"))
            .filter(|p| p.is_file())
            .unwrap_or_else(|| layout.backend_dir().join(".env.example"));
        let keys = KeyWriter::new(layout.env_file(), example, perms.clone());
        let stack = Stack::new(
            layout,
            bundle,
            runner.clone(),
            Arc::new(HttpProbe::new()),
            Arc::new(SystemClock),
            perms,
        );
        Ok(Self {
            os,
            version: version.to_string(),
            stack_root,
            env,
            runner,
            stack,
            keys,
        })
    }

    pub fn preflight(&self) -> PreflightReport {
        Preflight::new(
            self.os,
            self.runner.as_ref(),
            self.stack.layout.compose_file(),
            self.stack.layout.env_file(),
            Some(self.stack_root.clone()),
        )
        .check()
    }

    pub fn open_url(&self, url: &str) -> Result<(), String> {
        platform::open_url(self.os, self.runner.as_ref(), &self.env, url).map_err(|e| e.to_string())
    }
}

/// `<resources>/stack` from the installed app (tauri.conf.json bundles `../stack/` there);
/// under `tauri dev` / `cargo test` also `desktop/stack` or the repository's own project
/// folder, so development works without a packaging step. A bundled app (release, or
/// `tauri build --debug`) only ever installs the source it ships.
pub fn find_bundle(resource_dir: Option<PathBuf>) -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = resource_dir.into_iter().map(|r| r.join("stack")).collect();
    if tauri::is_dev() {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        candidates.push(manifest.join("..").join("stack"));
        candidates.push(manifest.join("..").join(".."));
    }
    candidates.into_iter().find(|c| looks_like_bundle(c))
}

// ── Job state (Tauri-free) ───────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobKind {
    Install,
    Start,
}

/// The install/start job as the setup window last saw it, so a reloaded window can
/// catch up without having received every event.
#[derive(Debug, Default)]
pub struct JobState {
    phase: Option<Phase>,
    error: Option<String>,
    busy: bool,
    started: Option<Instant>,
    finished: Option<Instant>,
    lines: VecDeque<String>,
}

impl JobState {
    /// Claim the job slot; false when one is already running.
    pub fn begin(&mut self) -> bool {
        if self.busy {
            return false;
        }
        *self = JobState {
            busy: true,
            started: Some(Instant::now()),
            ..JobState::default()
        };
        true
    }

    pub fn apply(&mut self, event: &StackEvent) {
        match event {
            StackEvent::Log(line) => {
                if self.lines.len() == MAX_JOB_LINES {
                    self.lines.pop_front();
                }
                self.lines.push_back(line.clone());
            }
            StackEvent::Phase(update) => {
                self.phase = Some(update.phase);
                self.error = update.error.clone();
                if !update.phase.is_active() {
                    self.finish();
                }
            }
        }
    }

    pub fn finish(&mut self) {
        self.busy = false;
        self.finished.get_or_insert_with(Instant::now);
    }

    pub fn is_busy(&self) -> bool {
        self.busy
    }

    pub fn snapshot(&self) -> JobSnapshot {
        let elapsed = match (self.started, self.finished) {
            (Some(start), Some(end)) => end.duration_since(start).as_secs(),
            (Some(start), None) => start.elapsed().as_secs(),
            _ => 0,
        };
        JobSnapshot {
            phase: self.phase.unwrap_or(Phase::Idle),
            busy: self.busy,
            error: self.error.clone(),
            elapsed_s: elapsed,
            lines: self.lines.iter().cloned().collect(),
        }
    }

    /// What `install_status()` reports. A running or failed job speaks for itself; otherwise
    /// (nothing run in this app session, or the last job ended healthy) the live stack
    /// decides: not installed → "idle", answering → "healthy", else "stopped". `healthy` is
    /// only called when the answer depends on it (it probes the backend over HTTP).
    pub fn status(&self, installed: bool, healthy: impl FnOnce() -> bool) -> PhaseEvent {
        let snap = self.snapshot();
        if self.busy {
            let phase = match self.phase {
                Some(phase) => phase_name(phase),
                // Claimed, but the job hasn't reported its first phase yet.
                None => "preparing",
            };
            return PhaseEvent::new(phase, snap.elapsed_s, snap.error);
        }
        if self.phase == Some(Phase::Failed) {
            return PhaseEvent::new("failed", snap.elapsed_s, snap.error);
        }
        if !installed {
            return PhaseEvent::new("idle", 0, None);
        }
        if healthy() {
            let elapsed = if self.phase == Some(Phase::Healthy) {
                snap.elapsed_s
            } else {
                0
            };
            PhaseEvent::new("healthy", elapsed, None)
        } else {
            PhaseEvent::new("stopped", 0, None)
        }
    }
}

/// The wire name of a phase (the same lowercase string `Phase` serializes to).
pub fn phase_name(phase: Phase) -> &'static str {
    match phase {
        Phase::Idle => "idle",
        Phase::Copying => "copying",
        Phase::Building => "building",
        Phase::Starting => "starting",
        Phase::Waiting => "waiting",
        Phase::Healthy => "healthy",
        Phase::Failed => "failed",
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct JobSnapshot {
    pub phase: Phase,
    pub busy: bool,
    pub error: Option<String>,
    pub elapsed_s: u64,
    pub lines: Vec<String>,
}

// ── Payloads (the UI's contract: desktop/ui/src/bridge.ts) ──────────────────

/// `install_status()` and the `stack://phase` event (which also carries `PhaseUpdate`, the
/// same shape with a typed phase).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PhaseEvent {
    pub phase: String,
    pub elapsed_s: u64,
    pub error: Option<String>,
}

impl PhaseEvent {
    fn new(phase: &str, elapsed_s: u64, error: Option<String>) -> Self {
        Self {
            phase: phase.to_string(),
            elapsed_s,
            error,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct OkResult {
    pub ok: bool,
}

/// `start_install()`: `ok` when this call started the job; `reason: "busy"` when an
/// install/start was already running (the UI then follows that one via `install_status`).
#[derive(Debug, Clone, Serialize)]
pub struct JobStart {
    pub ok: bool,
    pub started: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AppInfo {
    pub version: String,
    /// "mac" | "windows" (| "linux" on a dev machine; the UI treats that as unknown).
    pub platform: Os,
    /// The stack for this version is copied and has its keys: open on the status screen.
    pub installed: bool,
}

// ── Tauri state and helpers ──────────────────────────────────────────────────

/// Managed state. The core is built on first use (it needs the app's version and
/// resource folder, which exist only once the app runs), so `register` needs no
/// `setup` hook of its own.
#[derive(Default)]
pub struct DesktopState {
    core: OnceLock<Result<Arc<Core>, String>>,
    job: Arc<Mutex<JobState>>,
}

fn lock(job: &Mutex<JobState>) -> MutexGuard<'_, JobState> {
    job.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn core<R: Runtime>(app: &AppHandle<R>) -> Result<Arc<Core>, String> {
    let state = app.state::<DesktopState>();
    state
        .core
        .get_or_init(|| {
            let version = app.package_info().version.to_string();
            Core::new(&version, app.path().resource_dir().ok()).map(Arc::new)
        })
        .clone()
}

fn job<R: Runtime>(app: &AppHandle<R>) -> Arc<Mutex<JobState>> {
    app.state::<DesktopState>().job.clone()
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| format!("background task failed: {e}"))
}

fn emit_log<R: Runtime>(app: &AppHandle<R>, line: &str) {
    // The contract's log payload is the bare line.
    let _ = app.emit_to(SETUP_WINDOW, EVENT_LOG, line);
}

fn start_job<R: Runtime>(app: AppHandle<R>, kind: JobKind) -> Result<JobStart, String> {
    let core = core(&app)?;
    let job = job(&app);
    if !lock(&job).begin() {
        return Ok(JobStart {
            ok: false,
            started: false,
            reason: Some("busy".into()),
        });
    }
    let thread_job = job.clone();
    let spawned = std::thread::Builder::new()
        .name("crawler-ai-stack".into())
        .spawn(move || {
            let mut emit = |event: StackEvent| {
                lock(&thread_job).apply(&event);
                match &event {
                    StackEvent::Log(line) => emit_log(&app, line),
                    StackEvent::Phase(update) => {
                        let _ = app.emit_to(SETUP_WINDOW, EVENT_PHASE, update);
                    }
                }
            };
            let _ = match kind {
                JobKind::Install => core.stack.install(&mut emit),
                JobKind::Start => core.stack.start(&mut emit),
            };
            lock(&thread_job).finish();
        });
    if let Err(err) = spawned {
        lock(&job).finish();
        return Err(format!("could not start the background job: {err}"));
    }
    Ok(JobStart {
        ok: true,
        started: true,
        reason: None,
    })
}

/// Cancel a running install/start, `docker compose stop`, then tell the setup window the
/// stack is stopped. Blocks: call it off the main thread.
fn stop_stack<R: Runtime>(app: &AppHandle<R>) -> Result<(), String> {
    let core = core(app)?;
    let job = job(app);
    if lock(&job).is_busy() {
        core.stack.cancel();
        let deadline = Instant::now() + CANCEL_WAIT;
        while lock(&job).is_busy() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    emit_log(app, "$ docker compose -p crawler-ai stop");
    core.stack.stop()?;
    // The last job's phase no longer describes the stack; install_status asks the stack.
    *lock(&job) = JobState::default();
    emit_log(app, "Crawler AI is stopped. Your data is kept.");
    let _ = app.emit_to(
        SETUP_WINDOW,
        EVENT_PHASE,
        PhaseEvent::new("stopped", 0, None),
    );
    Ok(())
}

// ── Hooks for the app shell (main.rs, tray.rs, windows.rs) ───────────────────

/// The stack for this version has been copied and has its keys (it may be stopped).
pub fn is_installed<R: Runtime>(app: &AppHandle<R>) -> bool {
    core(app).map(|c| c.stack.is_installed()).unwrap_or(false)
}

/// Tray "Start": start the installed stack on a background thread and return at once;
/// progress goes to the setup window's `stack://phase` / `stack://log`.
pub fn start_stack_in_background<R: Runtime>(app: &AppHandle<R>) {
    match start_job(app.clone(), JobKind::Start) {
        Ok(started) if !started.started => {
            emit_log(app, "Crawler AI is already starting or installing.");
        }
        Ok(_) => {}
        Err(err) => emit_log(app, &format!("Couldn't start Crawler AI: {err}")),
    }
}

/// Tray "Stop": stop the stack on a background thread and return at once.
pub fn stop_stack_in_background<R: Runtime>(app: &AppHandle<R>) {
    let app = app.clone();
    let spawned = std::thread::Builder::new()
        .name("crawler-ai-stop".into())
        .spawn(move || {
            if let Err(err) = stop_stack(&app) {
                emit_log(&app, &format!("Couldn't stop Crawler AI: {err}"));
            }
        });
    if let Err(err) = spawned {
        eprintln!("crawler-ai: could not start the stop job: {err}");
    }
}

// ── Commands (names and payloads: desktop/ui/src/bridge.ts) ──────────────────

/// Step 1: Docker / Compose / ports / disk / keys checks. Read-only, except that an
/// upgraded app carries over the earlier version's keys first (so step 2 is skipped).
#[tauri::command(rename_all = "snake_case")]
async fn preflight<R: Runtime>(app: AppHandle<R>) -> Result<PreflightReport, String> {
    let core = core(&app)?;
    blocking(move || {
        let _ = core.stack.adopt_previous_env();
        core.preflight()
    })
    .await
}

/// Ask the OS to launch Docker Desktop; `{ok: false}` when it couldn't be opened.
#[tauri::command(rename_all = "snake_case")]
async fn open_docker_desktop<R: Runtime>(app: AppHandle<R>) -> Result<OkResult, String> {
    let core = core(&app)?;
    blocking(move || {
        let opened =
            platform::open_docker_desktop(core.os, core.runner.as_ref(), &core.env, &|p| {
                p.is_file()
            });
        OkResult { ok: opened.is_ok() }
    })
    .await
}

/// Step 2. `mode`: "generate" (the UI's default) or "custom" with both keys. The keys are
/// written to backend/.env and never sent back.
#[tauri::command(rename_all = "snake_case")]
async fn save_keys<R: Runtime>(
    app: AppHandle<R>,
    mode: String,
    secret_key: Option<String>,
    encryption_key: Option<String>,
    overwrite: Option<bool>,
) -> Result<WriteReport, String> {
    let key_mode = match mode.as_str() {
        "generate" => KeyMode::Generate,
        "custom" => KeyMode::Custom {
            secret_key: secret_key.unwrap_or_default(),
            encryption_key: encryption_key.unwrap_or_default(),
        },
        _ => {
            let mut errors = BTreeMap::new();
            errors.insert(
                "mode".to_string(),
                "Choose 'generate' or 'custom'.".to_string(),
            );
            return Ok(WriteReport::from(Err(crate::keys::KeyWriteError::Invalid(
                errors,
            ))));
        }
    };
    let core = core(&app)?;
    blocking(move || WriteReport::from(core.keys.write(key_mode, overwrite.unwrap_or(false)))).await
}

/// Step 3: copy the bundled source, build and start the stack; progress arrives as
/// `stack://phase` / `stack://log`.
#[tauri::command(rename_all = "snake_case")]
async fn start_install<R: Runtime>(app: AppHandle<R>) -> Result<JobStart, String> {
    start_job(app, JobKind::Install)
}

/// The current install/stack phase, so a reopened window can pick up where things are.
#[tauri::command(rename_all = "snake_case")]
async fn install_status<R: Runtime>(app: AppHandle<R>) -> Result<PhaseEvent, String> {
    let core = core(&app)?;
    let job = job(&app);
    blocking(move || {
        let installed = core.stack.is_installed();
        lock(&job).status(installed, || core.stack.backend_healthy())
    })
    .await
}

/// Step 4 / "Open Crawler AI": open (or focus) the Crawler AI window, which has no IPC
/// access, and hide the setup window. Async on purpose: building a window in a sync
/// command can deadlock on Windows.
#[tauri::command(rename_all = "snake_case")]
async fn open_crawler<R: Runtime>(app: AppHandle<R>) -> Result<(), String> {
    windows::open_crawler_window(&app).map_err(|e| e.to_string())
}

/// Start an installed stack and wait for it to be healthy (same events as the install).
#[tauri::command(rename_all = "snake_case")]
async fn stack_start<R: Runtime>(app: AppHandle<R>) -> Result<JobStart, String> {
    start_job(app, JobKind::Start)
}

/// Stop the stack (a running install/start is cancelled first). Data is kept.
#[tauri::command(rename_all = "snake_case")]
async fn stack_stop<R: Runtime>(app: AppHandle<R>) -> Result<(), String> {
    let handle = app.clone();
    blocking(move || stop_stack(&handle)).await?
}

#[tauri::command(rename_all = "snake_case")]
async fn app_info<R: Runtime>(app: AppHandle<R>) -> Result<AppInfo, String> {
    let version = app.package_info().version.to_string();
    let installed = blocking(move || is_installed(&app)).await?;
    Ok(AppInfo {
        version,
        platform: Os::current(),
        installed,
    })
}

/// Compare the running version with the newest desktop release on GitHub.
#[tauri::command(rename_all = "snake_case")]
async fn check_updates<R: Runtime>(app: AppHandle<R>) -> Result<UpdateInfo, String> {
    let current = app.package_info().version.clone();
    blocking(move || updates::check_now(&current)).await?
}

/// Manage the state and register every command. main.rs calls this once; `invoke_handler`
/// can only be set once per app, so further commands belong in the list below (build.rs
/// picks them up for the ACL on its own).
pub fn register<R: Runtime>(builder: tauri::Builder<R>) -> tauri::Builder<R> {
    builder
        .manage(DesktopState::default())
        .invoke_handler(tauri::generate_handler![
            preflight,
            open_docker_desktop,
            save_keys,
            start_install,
            install_status,
            open_crawler,
            stack_start,
            stack_stop,
            app_info,
            check_updates,
        ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stack::PhaseUpdate;
    use crate::test_support::FakeRunner;

    fn phase(phase: Phase, error: Option<&str>) -> StackEvent {
        StackEvent::Phase(PhaseUpdate {
            phase,
            error: error.map(str::to_string),
            elapsed_s: 1,
        })
    }

    #[test]
    fn job_state_tracks_one_job_at_a_time() {
        let mut job = JobState::default();
        assert_eq!(job.snapshot().phase, Phase::Idle);
        assert!(job.begin());
        assert!(!job.begin(), "a second job is refused while one runs");
        job.apply(&phase(Phase::Building, None));
        job.apply(&StackEvent::Log("line".into()));
        let snap = job.snapshot();
        assert!(snap.busy);
        assert_eq!(snap.phase, Phase::Building);
        assert_eq!(snap.lines, vec!["line".to_string()]);
        job.apply(&phase(Phase::Failed, Some("boom")));
        let snap = job.snapshot();
        assert!(!snap.busy);
        assert_eq!(snap.error.as_deref(), Some("boom"));
        assert!(job.begin(), "a retry may start after a failure");
        assert!(job.snapshot().lines.is_empty());
    }

    #[test]
    fn job_lines_are_capped() {
        let mut job = JobState::default();
        job.begin();
        for i in 0..(MAX_JOB_LINES + 5) {
            job.apply(&StackEvent::Log(i.to_string()));
        }
        let lines = job.snapshot().lines;
        assert_eq!(lines.len(), MAX_JOB_LINES);
        assert_eq!(lines[0], "5");
    }

    #[test]
    fn phase_names_match_the_serialized_phase() {
        for p in [
            Phase::Idle,
            Phase::Copying,
            Phase::Building,
            Phase::Starting,
            Phase::Waiting,
            Phase::Healthy,
            Phase::Failed,
        ] {
            assert_eq!(serde_json::to_value(p).unwrap(), phase_name(p));
        }
    }

    #[test]
    fn status_of_a_running_job_is_its_phase() {
        let mut job = JobState::default();
        job.begin();
        let never = || panic!("a running job must not probe the stack");
        assert_eq!(job.status(false, never).phase, "preparing");
        job.apply(&phase(Phase::Building, None));
        assert_eq!(job.status(true, never).phase, "building");
    }

    #[test]
    fn status_keeps_a_failure_until_the_next_job() {
        let mut job = JobState::default();
        job.begin();
        job.apply(&phase(Phase::Failed, Some("Docker isn't running")));
        let status = job.status(true, || true);
        assert_eq!(status.phase, "failed");
        assert_eq!(status.error.as_deref(), Some("Docker isn't running"));
    }

    #[test]
    fn status_without_a_job_asks_the_stack() {
        let job = JobState::default();
        assert_eq!(
            job.status(false, || panic!("not installed: no probe")),
            PhaseEvent::new("idle", 0, None)
        );
        assert_eq!(job.status(true, || true).phase, "healthy");
        assert_eq!(job.status(true, || false).phase, "stopped");
    }

    #[test]
    fn status_after_a_healthy_job_follows_the_live_stack() {
        let mut job = JobState::default();
        job.begin();
        job.apply(&phase(Phase::Healthy, None));
        assert_eq!(job.status(true, || true).phase, "healthy");
        // Stopped outside the app (Docker Desktop quit, CLI): no stale "healthy".
        assert_eq!(job.status(true, || false).phase, "stopped");
    }

    #[test]
    fn payloads_match_the_ui_contract() {
        let event = serde_json::to_value(PhaseEvent::new("stopped", 0, None)).unwrap();
        assert_eq!(
            event,
            serde_json::json!({"phase": "stopped", "elapsed_s": 0, "error": null})
        );
        let update = serde_json::to_value(PhaseUpdate {
            phase: Phase::Waiting,
            error: None,
            elapsed_s: 7,
        })
        .unwrap();
        assert_eq!(
            update,
            serde_json::json!({"phase": "waiting", "elapsed_s": 7, "error": null})
        );
        let start = serde_json::to_value(JobStart {
            ok: true,
            started: true,
            reason: None,
        })
        .unwrap();
        assert_eq!(start["ok"], true);
        let info = serde_json::to_value(AppInfo {
            version: "0.1.0".into(),
            platform: Os::Mac,
            installed: false,
        })
        .unwrap();
        assert_eq!(
            info,
            serde_json::json!({"version": "0.1.0", "platform": "mac", "installed": false})
        );
        let windows = serde_json::to_value(Os::Windows).unwrap();
        assert_eq!(windows, "windows");
    }

    /// The command list the UI calls (desktop/ui/src/bridge.ts) is exactly the list this
    /// module registers, so a rename on either side fails here.
    #[test]
    fn registered_commands_match_the_ui_bridge() {
        let bridge = include_str!("../../ui/src/bridge.ts");
        // Every `call<Type>("name"` in the bridge (the helper's own definition has no name).
        let mut ui: Vec<&str> = bridge
            .split("call<")
            .skip(1)
            .filter_map(|rest| rest.split_once(">(\""))
            .filter_map(|(_, name)| name.split('"').next())
            .collect();
        ui.sort_unstable();
        ui.dedup();
        let src = include_str!("commands.rs");
        let list = src
            .split("generate_handler![")
            .nth(1)
            .and_then(|rest| rest.split(']').next())
            .expect("generate_handler! list");
        let mut ours: Vec<&str> = list
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        ours.sort_unstable();
        assert_eq!(ui, ours);
    }

    #[test]
    fn core_uses_the_bundled_env_example_until_the_stack_is_copied() {
        let dir = tempfile::tempdir().unwrap();
        let bundle = dir.path().join("bundle");
        std::fs::create_dir_all(bundle.join("backend")).unwrap();
        std::fs::write(bundle.join("backend/.env.example"), "SECRET_KEY=x\n").unwrap();
        let runner: Arc<dyn CommandRunner> = Arc::new(FakeRunner::new());
        let core = Core::from_parts(
            Os::Mac,
            "1.0.0",
            dir.path().join("stack"),
            Some(bundle.clone()),
            BTreeMap::new(),
            runner.clone(),
        )
        .unwrap();
        assert_eq!(core.keys.example_path, bundle.join("backend/.env.example"));
        assert_eq!(
            core.keys.env_path,
            dir.path().join("stack/1.0.0/backend/.env")
        );
        let bare = Core::from_parts(
            Os::Mac,
            "1.0.0",
            dir.path().join("stack"),
            None,
            BTreeMap::new(),
            runner.clone(),
        )
        .unwrap();
        assert_eq!(
            bare.keys.example_path,
            dir.path().join("stack/1.0.0/backend/.env.example")
        );
        assert!(Core::from_parts(
            Os::Mac,
            "../x",
            dir.path().into(),
            None,
            BTreeMap::new(),
            runner
        )
        .is_err());
    }

    #[cfg(debug_assertions)]
    #[test]
    fn debug_builds_find_the_repository_as_a_bundle() {
        // desktop/src-tauri/../.. is the project folder with backend/, frontend/, docker/.
        let found = find_bundle(None).expect("repository checkout serves as the dev bundle");
        assert!(looks_like_bundle(&found));
    }
}

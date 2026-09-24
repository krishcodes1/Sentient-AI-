//! Test doubles for the three seams the core logic runs through: `CommandRunner` (no
//! real docker/icacls/open ever runs in a test), `HealthProbe` and `Clock` (health polling
//! finishes instantly on a fake clock).
//!
//! Why it exists: the unit tests must pass on a machine with no Docker, without touching
//! the real stack or its ports, and on Mac and Windows CI alike.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::platform::{Os, OwnerOnly};
use crate::preflight::{CmdError, CmdOutput, CommandRunner};
use crate::stack::{Clock, HealthProbe};

#[derive(Clone)]
struct Scripted {
    output: CmdOutput,
    lines: Vec<String>,
}

/// Answers commands by substring match on the space-joined argv (longest key wins);
/// anything unscripted exits 0 with no output. `which` finds every program in
/// /fake/bin unless marked missing.
#[derive(Default)]
pub struct FakeRunner {
    scripts: Mutex<BTreeMap<String, Scripted>>,
    missing: Mutex<BTreeSet<String>>,
    calls: Mutex<Vec<Vec<String>>>,
    streamed: Mutex<Vec<(Vec<String>, Option<PathBuf>)>>,
    detached: Mutex<Vec<Vec<String>>>,
}

impl FakeRunner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn respond(&self, key: &str, code: i32, stdout: &str) {
        self.scripts.lock().unwrap().insert(
            key.to_string(),
            Scripted {
                output: CmdOutput::exited(code, stdout),
                lines: Vec::new(),
            },
        );
    }

    pub fn stream_lines(&self, key: &str, code: i32, lines: &[&str]) {
        self.scripts.lock().unwrap().insert(
            key.to_string(),
            Scripted {
                output: CmdOutput::exited(code, ""),
                lines: lines.iter().map(|l| l.to_string()).collect(),
            },
        );
    }

    pub fn stream_error(&self, key: &str, error: CmdError) {
        self.scripts.lock().unwrap().insert(
            key.to_string(),
            Scripted {
                output: CmdOutput::failed(error),
                lines: Vec::new(),
            },
        );
    }

    pub fn missing(&self, program: &str) {
        self.missing.lock().unwrap().insert(program.to_string());
    }

    /// argv of every `run` and `stream` call, in order.
    pub fn calls(&self) -> Vec<Vec<String>> {
        self.calls.lock().unwrap().clone()
    }

    /// argv and cwd of every `stream` call.
    pub fn streamed(&self) -> Vec<(Vec<String>, Option<PathBuf>)> {
        self.streamed.lock().unwrap().clone()
    }

    pub fn detached(&self) -> Vec<Vec<String>> {
        self.detached.lock().unwrap().clone()
    }

    fn lookup(&self, argv: &[String]) -> Scripted {
        let joined = argv.join(" ");
        let scripts = self.scripts.lock().unwrap();
        scripts
            .iter()
            .filter(|(key, _)| joined.contains(key.as_str()))
            .max_by_key(|(key, _)| key.len())
            .map(|(_, s)| s.clone())
            .unwrap_or(Scripted {
                output: CmdOutput::exited(0, ""),
                lines: Vec::new(),
            })
    }
}

impl CommandRunner for FakeRunner {
    fn which(&self, program: &str) -> Option<PathBuf> {
        if self.missing.lock().unwrap().contains(program) {
            None
        } else {
            Some(PathBuf::from("/fake/bin").join(program))
        }
    }

    fn run(&self, argv: &[String], _cwd: Option<&Path>, _timeout: Duration) -> CmdOutput {
        self.calls.lock().unwrap().push(argv.to_vec());
        self.lookup(argv).output
    }

    fn stream(
        &self,
        argv: &[String],
        cwd: Option<&Path>,
        _timeout: Duration,
        _cancel: &AtomicBool,
        on_line: &mut dyn FnMut(&str),
    ) -> CmdOutput {
        self.calls.lock().unwrap().push(argv.to_vec());
        self.streamed
            .lock()
            .unwrap()
            .push((argv.to_vec(), cwd.map(Path::to_path_buf)));
        let scripted = self.lookup(argv);
        for line in &scripted.lines {
            on_line(line);
        }
        scripted.output
    }

    fn spawn_detached(&self, argv: &[String]) -> Result<(), CmdError> {
        self.detached.lock().unwrap().push(argv.to_vec());
        Ok(())
    }
}

static NET_LOCK: Mutex<()> = Mutex::new(());

/// Serialises the few tests that open real loopback sockets on ephemeral ports.
pub fn net_lock() -> std::sync::MutexGuard<'static, ()> {
    NET_LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

/// A FakeRunner that answers `whoami /user` like Windows does, so owner-only writes work
/// in tests on every OS (icacls itself is faked to succeed).
pub fn runner_with_account() -> Arc<FakeRunner> {
    let runner = Arc::new(FakeRunner::new());
    runner.respond(
        "whoami.exe",
        0,
        "\"pc\\tester\",\"S-1-5-21-1-2-3-1001\"\r\n",
    );
    runner
}

/// Owner-only file handling for the OS the tests run on, backed by a fake runner.
pub fn owner_only(runner: Arc<FakeRunner>) -> OwnerOnly {
    OwnerOnly::new(Os::current(), runner, BTreeMap::new())
}

/// `set(url, n)`: the first n probes of `url` fail, then it is healthy. Unset URLs never
/// answer.
#[derive(Default)]
pub struct ScriptedProbe {
    remaining: Mutex<BTreeMap<String, u32>>,
}

impl ScriptedProbe {
    pub fn set(&self, url: &str, failures_before_ok: u32) {
        self.remaining
            .lock()
            .unwrap()
            .insert(url.to_string(), failures_before_ok);
    }
}

impl HealthProbe for ScriptedProbe {
    fn ok(&self, url: &str) -> bool {
        let mut remaining = self.remaining.lock().unwrap();
        match remaining.get_mut(url) {
            Some(0) => true,
            Some(n) => {
                *n -= 1;
                false
            }
            None => false,
        }
    }
}

/// Time only moves when something sleeps.
pub struct FakeClock {
    start: Instant,
    offset: Mutex<Duration>,
}

impl FakeClock {
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
            offset: Mutex::new(Duration::ZERO),
        }
    }

    pub fn slept(&self) -> Duration {
        *self.offset.lock().unwrap()
    }
}

impl Clock for FakeClock {
    fn now(&self) -> Instant {
        self.start + *self.offset.lock().unwrap()
    }

    fn sleep(&self, duration: Duration) {
        *self.offset.lock().unwrap() += duration;
    }
}

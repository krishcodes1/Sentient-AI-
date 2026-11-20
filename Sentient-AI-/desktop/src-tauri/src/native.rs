//! The native macOS stack: where its pieces live and how the app talks to
//! `mac/crawler-native.sh`, which installs, starts and stops Crawler AI without Docker.
//!
//! Why it exists: on a Mac the app runs Crawler AI as its own child processes (Postgres on a
//! Unix socket, the backend on 127.0.0.1:3000 serving the built web app), so screen and
//! computer control work and macOS asks for permissions in the app's name. The script does
//! the work; this module builds its command line and reads its output, and `Stack` (stack.rs)
//! drives it through the same phases, job state and UI as the Docker stack.
//!
//! The script's output contract: `==> building` / `==> starting` start a phase, `error: <text>`
//! is the plain-English failure, every other line is log.

use std::fs;
use std::path::{Path, PathBuf};

use crate::platform::APP_DIR_NAME;

/// The backend answers the web app and the API on one origin, the OAuth redirect base.
pub const HEALTH_URL: &str = "http://127.0.0.1:3000/api/health";
pub const FRONTEND_URL: &str = "http://127.0.0.1:3000/";
/// Relative to a version's stack folder.
pub const SCRIPT: &str = "mac/crawler-native.sh";

/// Where the native stack's pieces are. Built once per app run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeLayout {
    /// `~/Library/Application Support/Crawler AI/native`: venv, Python, Chromium, database,
    /// socket, pid file, logs.
    pub home: PathBuf,
    /// `~/Library/Caches/Crawler AI`: only uv's download cache.
    pub cache: PathBuf,
    /// The bundled uv (a Tauri sidecar next to the app's executable).
    pub uv: PathBuf,
    /// The bundled PostgreSQL (`<resources>/postgres`, with bin/ lib/ share/).
    pub pg: PathBuf,
}

/// What one line of the script's output means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    Building,
    Starting,
    Error(String),
    Log(String),
}

impl NativeLayout {
    /// `stack_root` is `<Application Support>/Crawler AI/stack`; `home` is its sibling.
    pub fn new(stack_root: &Path, cache_dir: &Path, exe_dir: &Path, resource_dir: &Path) -> Self {
        let app_dir = stack_root.parent().unwrap_or(stack_root);
        Self {
            home: app_dir.join("native"),
            cache: cache_dir.join(APP_DIR_NAME),
            uv: exe_dir.join("uv"),
            pg: resource_dir.join("postgres"),
        }
    }

    /// The layout for the running app, or None when the app doesn't carry uv and Postgres:
    /// only the Mac release build bundles them (`npm run build:mac`, which adds
    /// tauri.mac-native.conf.json). `tauri dev` and plain builds keep the Docker stack.
    pub fn for_this_app(stack_root: &Path, resource_dir: Option<PathBuf>) -> Option<Self> {
        let cache = dirs::cache_dir()?;
        let exe = std::env::current_exe().ok()?;
        let layout = Self::new(stack_root, &cache, exe.parent()?, &resource_dir?);
        layout.is_bundled().then_some(layout)
    }

    pub fn is_bundled(&self) -> bool {
        self.uv.is_file() && self.pg.join("bin").join("postgres").is_file()
    }

    /// Holds the version that last came up healthy: "installed" means this version's
    /// packages, browser and database are in place and it has answered once.
    pub fn installed_marker(&self) -> PathBuf {
        self.home.join("installed-version")
    }

    pub fn backend_log(&self) -> PathBuf {
        self.home.join("logs").join("backend.log")
    }

    pub fn is_installed(&self, version: &str) -> bool {
        fs::read_to_string(self.installed_marker()).is_ok_and(|v| v.trim() == version)
    }

    pub fn mark_installed(&self, version: &str) -> std::io::Result<()> {
        fs::create_dir_all(&self.home)?;
        fs::write(self.installed_marker(), format!("{version}\n"))
    }

    /// `/usr/bin/env CRAWLER_…=… /bin/bash <stack_dir>/mac/crawler-native.sh <command>`.
    /// The paths go through env, not a shell, so spaces ("Application Support") are safe.
    pub fn argv(&self, stack_dir: &Path, command: &str) -> Vec<String> {
        let var = |name: &str, path: &Path| format!("{name}={}", path.display());
        vec![
            "/usr/bin/env".into(),
            var("CRAWLER_STACK", stack_dir),
            var("CRAWLER_HOME", &self.home),
            var("CRAWLER_CACHE", &self.cache),
            var("CRAWLER_UV", &self.uv),
            var("CRAWLER_PG", &self.pg),
            "/bin/bash".into(),
            stack_dir.join(SCRIPT).display().to_string(),
            command.into(),
        ]
    }
}

pub fn parse_line(line: &str) -> Line {
    match line.trim_end() {
        "==> building" => Line::Building,
        "==> starting" => Line::Starting,
        other => match other.strip_prefix("error: ") {
            Some(message) => Line::Error(message.trim().to_string()),
            None => Line::Log(other.to_string()),
        },
    }
}

/// The last `lines` lines of a log file (empty when it doesn't exist yet).
pub fn tail(path: &Path, lines: usize) -> Vec<String> {
    let Ok(text) = fs::read(path) else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&text);
    let all: Vec<&str> = text.lines().collect();
    all[all.len().saturating_sub(lines)..]
        .iter()
        .map(|l| l.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout() -> NativeLayout {
        NativeLayout::new(
            Path::new("/Users/a/Library/Application Support/Crawler AI/stack"),
            Path::new("/Users/a/Library/Caches"),
            Path::new("/Applications/Crawler AI.app/Contents/MacOS"),
            Path::new("/Applications/Crawler AI.app/Contents/Resources"),
        )
    }

    #[test]
    fn paths_sit_beside_the_stack_and_inside_the_app() {
        let n = layout();
        assert_eq!(
            n.home,
            Path::new("/Users/a/Library/Application Support/Crawler AI/native")
        );
        assert_eq!(n.cache, Path::new("/Users/a/Library/Caches/Crawler AI"));
        assert_eq!(
            n.uv,
            Path::new("/Applications/Crawler AI.app/Contents/MacOS/uv")
        );
        assert_eq!(
            n.pg,
            Path::new("/Applications/Crawler AI.app/Contents/Resources/postgres")
        );
    }

    #[test]
    fn argv_passes_paths_through_env_not_a_shell() {
        let stack = Path::new("/Users/a/Library/Application Support/Crawler AI/stack/1.0.0");
        let argv = layout().argv(stack, "install");
        assert_eq!(argv[0], "/usr/bin/env");
        assert!(argv.contains(
            &"CRAWLER_HOME=/Users/a/Library/Application Support/Crawler AI/native".to_string()
        ));
        assert!(argv.contains(
            &"CRAWLER_STACK=/Users/a/Library/Application Support/Crawler AI/stack/1.0.0"
                .to_string()
        ));
        assert_eq!(
            &argv[argv.len() - 3..],
            &[
                "/bin/bash".to_string(),
                format!("{}/mac/crawler-native.sh", stack.display()),
                "install".to_string()
            ]
        );
    }

    #[test]
    fn lines_map_to_phases_errors_and_log() {
        assert_eq!(parse_line("==> building"), Line::Building);
        assert_eq!(parse_line("==> starting\n"), Line::Starting);
        assert_eq!(
            parse_line("error: Port 3000 is in use by node (pid 7)."),
            Line::Error("Port 3000 is in use by node (pid 7).".into())
        );
        assert_eq!(
            parse_line("    Python 3.12.13"),
            Line::Log("    Python 3.12.13".into())
        );
        assert_eq!(
            parse_line("an error: in the middle"),
            Line::Log("an error: in the middle".into())
        );
    }

    #[test]
    fn installed_means_this_version_came_up() {
        let dir = tempfile::tempdir().unwrap();
        let n = NativeLayout::new(
            &dir.path().join("Crawler AI").join("stack"),
            dir.path(),
            dir.path(),
            dir.path(),
        );
        assert!(!n.is_installed("1.0.0"));
        n.mark_installed("1.0.0").unwrap();
        assert!(n.is_installed("1.0.0"));
        assert!(!n.is_installed("1.1.0"), "a new app version installs again");
    }

    #[test]
    fn tail_reads_the_last_lines() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("backend.log");
        assert!(tail(&log, 5).is_empty());
        fs::write(&log, "a\nb\nc\n").unwrap();
        assert_eq!(tail(&log, 2), vec!["b", "c"]);
        assert_eq!(tail(&log, 10), vec!["a", "b", "c"]);
    }
}

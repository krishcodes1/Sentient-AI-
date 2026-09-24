//! Per-OS facts the rest of the app should not have to know: where the stack lives,
//! which environment reaches `docker`, how a file is made owner-only, and how Docker
//! Desktop or a web page is opened.
//!
//! Why it exists: Mac and Windows differ in every one of these (Application Support vs
//! %LOCALAPPDATA%, 0600 vs an ACL, `open -a` vs an .exe) and a Finder-launched app gets a
//! trimmed PATH that does not include Docker's CLI. Keeping the differences here, as
//! functions that take the OS as a value, lets the tests exercise the Windows branches on
//! a Mac (commands go through a fake `CommandRunner`).

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;

use crate::preflight::{CmdError, CommandRunner};

/// Folder under the per-user data directory that holds everything the app writes.
pub const APP_DIR_NAME: &str = "Crawler AI";
/// Sub-folder holding one copy of the bundled source per app version.
pub const STACK_DIR_NAME: &str = "stack";
pub const DOCKER_DESKTOP_URL: &str = "https://www.docker.com/products/docker-desktop/";

/// Where Docker Desktop and Homebrew put binaries on macOS/Linux. A Finder-launched app
/// starts with PATH=/usr/bin:/bin:/usr/sbin:/sbin, which has none of them.
const POSIX_EXTRA_PATH_DIRS: &[&str] = &[
    "/usr/local/bin",
    "/opt/homebrew/bin",
    "~/.docker/bin",
    "/Applications/Docker.app/Contents/Resources/bin",
    "/usr/bin",
    "/bin",
    "/usr/sbin",
    "/sbin",
];
/// Docker Desktop for Windows' CLI folders, relative to %ProgramFiles% / %ProgramData%.
const WINDOWS_EXTRA_PATH_DIRS: &[(&str, &str)] = &[
    ("PROGRAMFILES", "Docker\\Docker\\resources\\bin"),
    ("PROGRAMDATA", "DockerDesktop\\version-bin"),
];
/// The only variables that reach docker besides PATH (same list as
/// installer/bootstrap.py). No COMPOSE_FILE (it would build a different stack) and
/// nothing that could carry an API key from the user's shell.
pub const ENV_ALLOWLIST: &[&str] = &[
    "HOME",
    "USER",
    "LOGNAME",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_CONFIG",
    "DOCKER_CERT_PATH",
    "DOCKER_TLS_VERIFY",
    "DOCKER_DEFAULT_PLATFORM",
    "DOCKER_BUILDKIT",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
];
/// Windows programs (Docker's CLI included) misbehave without these.
pub const WINDOWS_ENV_ALLOWLIST: &[&str] = &[
    "SYSTEMROOT",
    "WINDIR",
    "SYSTEMDRIVE",
    "COMSPEC",
    "PATHEXT",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "USERNAME",
    "USERDOMAIN",
    "HOMEDRIVE",
    "HOMEPATH",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "PROGRAMW6432",
    "COMPUTERNAME",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Os {
    Mac,
    Windows,
    Linux,
}

impl Os {
    pub fn current() -> Self {
        if cfg!(target_os = "macos") {
            Os::Mac
        } else if cfg!(windows) {
            Os::Windows
        } else {
            Os::Linux
        }
    }

    fn path_list_separator(self) -> char {
        if self == Os::Windows {
            ';'
        } else {
            ':'
        }
    }
}

// ── Paths ─────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PathError {
    #[error("this computer has no per-user data folder")]
    NoDataDir,
    #[error("invalid app version {0:?}")]
    BadVersion(String),
}

/// `<data>/Crawler AI/stack`: Application Support on Mac, %LOCALAPPDATA% on Windows,
/// ~/.local/share on Linux (development only). Pure so each OS branch is testable.
pub fn stack_root_for(
    os: Os,
    data_dir: Option<&Path>,
    data_local_dir: Option<&Path>,
) -> Result<PathBuf, PathError> {
    let base = match os {
        Os::Mac => data_dir,
        Os::Windows | Os::Linux => data_local_dir,
    }
    .ok_or(PathError::NoDataDir)?;
    Ok(base.join(APP_DIR_NAME).join(STACK_DIR_NAME))
}

/// The stack root for the running OS and user.
pub fn default_stack_root() -> Result<PathBuf, PathError> {
    stack_root_for(
        Os::current(),
        dirs::data_dir().as_deref(),
        dirs::data_local_dir().as_deref(),
    )
}

/// `<root>/<version>`; the version must be a plain name (no separators, no `..`).
pub fn version_dir(root: &Path, version: &str) -> Result<PathBuf, PathError> {
    let valid = !version.is_empty()
        && version.len() <= 64
        && version != "."
        && version != ".."
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+'));
    if !valid {
        return Err(PathError::BadVersion(version.chars().take(64).collect()));
    }
    Ok(root.join(version))
}

// ── Environment for child processes ──────────────────────────────────────────

/// Case-insensitive lookup (Windows environment names ignore case); an exact match wins.
pub fn env_get<'a>(source: &'a [(String, String)], name: &str) -> Option<&'a str> {
    if let Some((_, v)) = source.iter().find(|(k, _)| k == name) {
        return Some(v.as_str());
    }
    source
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn extra_path_dirs(os: Os, source: &[(String, String)], home: Option<&Path>) -> Vec<String> {
    match os {
        Os::Windows => WINDOWS_EXTRA_PATH_DIRS
            .iter()
            .filter_map(|(var, sub)| {
                env_get(source, var)
                    .filter(|b| !b.is_empty())
                    .map(|b| format!("{}\\{}", b.trim_end_matches('\\'), sub))
            })
            .collect(),
        _ => POSIX_EXTRA_PATH_DIRS
            .iter()
            .filter_map(|d| match d.strip_prefix("~/") {
                // Joined with '/' by hand: these are POSIX paths even when tests run on
                // Windows.
                Some(rest) => {
                    home.map(|h| format!("{}/{rest}", h.to_string_lossy().trim_end_matches('/')))
                }
                None => Some((*d).to_string()),
            })
            .collect(),
    }
}

/// The inherited PATH plus Docker's usual install folders (appended, deduplicated).
pub fn augmented_path(os: Os, source: &[(String, String)], home: Option<&Path>) -> String {
    let sep = os.path_list_separator();
    let current = env_get(source, "PATH").unwrap_or("");
    let mut parts: Vec<String> = current
        .split(sep)
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect();
    for extra in extra_path_dirs(os, source, home) {
        if !parts.contains(&extra) {
            parts.push(extra);
        }
    }
    parts.join(&sep.to_string())
}

/// Minimal environment for docker/lsof/icacls: PATH, HOME/USERPROFILE, Docker and proxy
/// variables, plus the handful Windows itself needs. Mirrors bootstrap.py's build_env.
pub fn build_env(
    os: Os,
    source: &[(String, String)],
    home: Option<&Path>,
) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    if os == Os::Windows {
        for (key, value) in source {
            let upper = key.to_ascii_uppercase();
            let allowed = ENV_ALLOWLIST
                .iter()
                .chain(WINDOWS_ENV_ALLOWLIST)
                .any(|a| a.eq_ignore_ascii_case(&upper));
            if allowed {
                env.insert(key.clone(), value.clone());
            }
        }
    } else {
        for name in ENV_ALLOWLIST {
            if let Some((_, v)) = source.iter().find(|(k, _)| k == name) {
                env.insert((*name).to_string(), v.clone());
            }
        }
        if !env.contains_key("HOME") {
            if let Some(h) = home {
                env.insert("HOME".into(), h.to_string_lossy().into_owned());
            }
        }
    }
    env.insert("PATH".into(), augmented_path(os, source, home));
    // Plain, colourless output reads well in the log panel.
    env.insert("COMPOSE_ANSI".into(), "never".into());
    env.insert("BUILDKIT_PROGRESS".into(), "plain".into());
    env
}

/// The current process environment as UTF-8 pairs (non-UTF-8 entries are dropped).
pub fn process_env() -> Vec<(String, String)> {
    std::env::vars_os()
        .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
        .collect()
}

/// Find `program` on a PATH string, like `shutil.which`.
pub fn which_in(program: &str, path: &str, os: Os) -> Option<PathBuf> {
    let candidates: Vec<String> = if os == Os::Windows && !program.contains('.') {
        vec![
            format!("{program}.exe"),
            format!("{program}.cmd"),
            program.to_string(),
        ]
    } else {
        vec![program.to_string()]
    };
    for dir in path
        .split(os.path_list_separator())
        .filter(|d| !d.is_empty())
    {
        for name in &candidates {
            let full = Path::new(dir).join(name);
            if is_executable(&full) {
                return Some(full);
            }
        }
    }
    None
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

/// `%SystemRoot%\System32\<exe>`: Windows tools are run by absolute path so a folder
/// earlier on PATH cannot substitute them.
fn system32(env: &BTreeMap<String, String>, exe: &str) -> String {
    let root = env
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("SYSTEMROOT"))
        .map(|(_, v)| v.trim_end_matches('\\').to_string())
        .unwrap_or_else(|| "C:\\Windows".to_string());
    format!("{root}\\System32\\{exe}")
}

// ── Owner-only files ─────────────────────────────────────────────────────────

/// Makes files private to the current user: mode 0600 on Mac/Linux, an explicit ACL
/// (inheritance removed, full control for this account only) on Windows via icacls.
#[derive(Clone)]
pub struct OwnerOnly {
    os: Os,
    runner: Arc<dyn CommandRunner>,
    env: BTreeMap<String, String>,
}

impl OwnerOnly {
    pub fn new(os: Os, runner: Arc<dyn CommandRunner>, env: BTreeMap<String, String>) -> Self {
        Self { os, runner, env }
    }

    /// The icacls trustee for this account: `*<SID>` from `whoami /user` (works for
    /// local, domain and Microsoft accounts alike), else `DOMAIN\USERNAME`, else USERNAME.
    pub fn windows_trustee(&self) -> Option<String> {
        let argv = vec![
            system32(&self.env, "whoami.exe"),
            "/user".into(),
            "/fo".into(),
            "csv".into(),
            "/nh".into(),
        ];
        let out = self.runner.run(&argv, None, Duration::from_secs(15));
        if out.ok() {
            if let Some(sid) = parse_whoami_sid(&out.stdout) {
                return Some(format!("*{sid}"));
            }
        }
        let get = |name: &str| {
            self.env
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let user = get("USERNAME")?;
        Some(match get("USERDOMAIN") {
            Some(domain) => format!("{domain}\\{user}"),
            None => user,
        })
    }

    /// Restrict an existing file to its owner.
    pub fn restrict(&self, path: &Path) -> io::Result<()> {
        match self.os {
            Os::Windows => {
                let trustee = self.windows_trustee().ok_or_else(|| {
                    io::Error::other("could not tell which Windows account to grant access to")
                })?;
                let argv = vec![
                    system32(&self.env, "icacls.exe"),
                    path.to_string_lossy().into_owned(),
                    "/inheritance:r".into(),
                    "/grant:r".into(),
                    format!("{trustee}:F"),
                ];
                let out = self.runner.run(&argv, None, Duration::from_secs(30));
                if out.ok() {
                    Ok(())
                } else {
                    Err(io::Error::other(format!(
                        "icacls could not make the file private ({})",
                        out.describe_failure()
                    )))
                }
            }
            Os::Mac | Os::Linux => chmod_600(path),
        }
    }

    /// Create `path` (which must not exist) holding `data`, private before any byte of
    /// `data` is written.
    pub fn create_new(&self, path: &Path, data: &[u8]) -> io::Result<()> {
        let file = create_new_private(path)?;
        if self.os == Os::Windows {
            drop(file);
            if let Err(err) = self.restrict(path) {
                let _ = fs::remove_file(path);
                return Err(err);
            }
            let mut file = OpenOptions::new().write(true).truncate(true).open(path)?;
            file.write_all(data)?;
            file.sync_all()?;
        } else {
            let mut file = file;
            file.write_all(data)?;
            file.sync_all()?;
            drop(file);
            self.restrict(path)?;
        }
        Ok(())
    }

    /// Atomically replace `path` with `data`; the result is owner-only.
    pub fn write_atomic(&self, path: &Path, data: &[u8]) -> io::Result<()> {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "file".into());
        let mut suffix = [0u8; 4];
        getrandom::fill(&mut suffix).map_err(|e| io::Error::other(e.to_string()))?;
        let tmp = path.with_file_name(format!(
            ".{name}.tmp-{}-{:02x}{:02x}{:02x}{:02x}",
            std::process::id(),
            suffix[0],
            suffix[1],
            suffix[2],
            suffix[3]
        ));
        let result = self
            .create_new(&tmp, data)
            .and_then(|()| fs::rename(&tmp, path));
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
            return result;
        }
        // The rename keeps the temp file's mode/ACL; re-apply on POSIX in case a umask or
        // a pre-existing target interfered.
        if self.os != Os::Windows {
            self.restrict(path)?;
        }
        Ok(())
    }
}

/// The SID from `whoami /user /fo csv /nh` output: `"host\user","S-1-5-21-..."`.
pub fn parse_whoami_sid(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        line.split(',')
            .map(|f| f.trim().trim_matches('"'))
            .find(|f| {
                f.starts_with("S-1-")
                    && f.len() <= 200
                    && f[4..].chars().all(|c| c.is_ascii_digit() || c == '-')
            })
            .map(str::to_string)
    })
}

#[cfg(unix)]
fn create_new_private(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_new_private(path: &Path) -> io::Result<fs::File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

#[cfg(unix)]
fn chmod_600(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn chmod_600(_path: &Path) -> io::Result<()> {
    Ok(())
}

// ── Docker Desktop and the browser ───────────────────────────────────────────

/// Docker Desktop's executable on Windows (`%ProgramFiles%\Docker\Docker\Docker Desktop.exe`).
pub fn docker_desktop_exe(env: &BTreeMap<String, String>) -> PathBuf {
    let base = env
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("PROGRAMFILES"))
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| "C:\\Program Files".to_string());
    PathBuf::from(format!(
        "{}\\Docker\\Docker\\Docker Desktop.exe",
        base.trim_end_matches('\\')
    ))
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OpenError {
    #[error("Docker Desktop isn't installed in the usual place")]
    NotInstalled,
    #[error("opening it isn't supported on this system")]
    Unsupported,
    #[error("only web links can be opened")]
    NotAWebLink,
    #[error("could not open it ({0})")]
    Failed(String),
}

/// Launch Docker Desktop; it keeps running on its own. `exists` is injected so tests do
/// not depend on what is installed.
pub fn open_docker_desktop(
    os: Os,
    runner: &dyn CommandRunner,
    env: &BTreeMap<String, String>,
    exists: &dyn Fn(&Path) -> bool,
) -> Result<(), OpenError> {
    match os {
        Os::Mac => {
            let argv = vec!["/usr/bin/open".into(), "-a".into(), "Docker".into()];
            let out = runner.run(&argv, None, Duration::from_secs(15));
            if out.ok() {
                Ok(())
            } else {
                Err(OpenError::Failed(out.describe_failure()))
            }
        }
        Os::Windows => {
            // Spawned directly (no `cmd /c start`, no shell), detached like a double-click.
            let exe = docker_desktop_exe(env);
            if !exists(&exe) {
                return Err(OpenError::NotInstalled);
            }
            runner
                .spawn_detached(&[exe.to_string_lossy().into_owned()])
                .map_err(|e| OpenError::Failed(e.to_string()))
        }
        Os::Linux => Err(OpenError::Unsupported),
    }
}

/// argv that opens an http(s) URL in the default browser, or None for anything else.
pub fn open_url_argv(os: Os, url: &str, env: &BTreeMap<String, String>) -> Option<Vec<String>> {
    let lower = url.to_ascii_lowercase();
    let web = (lower.starts_with("https://") || lower.starts_with("http://"))
        && url.len() <= 2048
        && !url
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == '"');
    if !web {
        return None;
    }
    Some(match os {
        Os::Mac => vec!["/usr/bin/open".into(), url.into()],
        Os::Windows => vec![
            system32(env, "rundll32.exe"),
            "url.dll,FileProtocolHandler".into(),
            url.into(),
        ],
        Os::Linux => vec!["xdg-open".into(), url.into()],
    })
}

/// Open an http(s) URL in the user's browser.
pub fn open_url(
    os: Os,
    runner: &dyn CommandRunner,
    env: &BTreeMap<String, String>,
    url: &str,
) -> Result<(), OpenError> {
    let argv = open_url_argv(os, url, env).ok_or(OpenError::NotAWebLink)?;
    runner
        .spawn_detached(&argv)
        .map_err(|e: CmdError| OpenError::Failed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::FakeRunner;

    fn pairs(items: &[(&str, &str)]) -> Vec<(String, String)> {
        items
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn stack_root_per_os() {
        let data = Path::new("/Users/a/Library/Application Support");
        let local = Path::new("C:\\Users\\a\\AppData\\Local");
        assert_eq!(
            stack_root_for(Os::Mac, Some(data), Some(local)).unwrap(),
            data.join("Crawler AI").join("stack")
        );
        assert_eq!(
            stack_root_for(Os::Windows, Some(data), Some(local)).unwrap(),
            local.join("Crawler AI").join("stack")
        );
        assert_eq!(
            stack_root_for(Os::Linux, Some(data), Some(local)).unwrap(),
            local.join("Crawler AI").join("stack")
        );
        assert_eq!(
            stack_root_for(Os::Mac, None, Some(local)),
            Err(PathError::NoDataDir)
        );
    }

    #[test]
    fn default_stack_root_ends_with_app_and_stack() {
        let root = default_stack_root().unwrap();
        assert!(root.ends_with(Path::new("Crawler AI").join("stack")));
    }

    #[test]
    fn version_dir_rejects_traversal() {
        let root = Path::new("/r");
        assert_eq!(version_dir(root, "1.2.3").unwrap(), root.join("1.2.3"));
        assert_eq!(
            version_dir(root, "1.0.0-beta.1+b7").unwrap(),
            root.join("1.0.0-beta.1+b7")
        );
        for bad in ["", ".", "..", "../x", "a/b", "a\\b", "1 0"] {
            assert!(version_dir(root, bad).is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn build_env_posix_keeps_only_allowlisted() {
        let src = pairs(&[
            ("PATH", "/usr/bin:/bin"),
            ("HOME", "/Users/a"),
            ("OPENAI_API_KEY", "sk-nope"),
            ("COMPOSE_FILE", "/elsewhere.yml"),
            ("DOCKER_HOST", "unix:///x.sock"),
        ]);
        let env = build_env(Os::Mac, &src, Some(Path::new("/Users/a")));
        assert!(!env.contains_key("OPENAI_API_KEY"));
        assert!(!env.contains_key("COMPOSE_FILE"));
        assert_eq!(env["DOCKER_HOST"], "unix:///x.sock");
        assert_eq!(env["COMPOSE_ANSI"], "never");
        assert_eq!(env["BUILDKIT_PROGRESS"], "plain");
        let path: Vec<&str> = env["PATH"].split(':').collect();
        assert_eq!(&path[..2], &["/usr/bin", "/bin"]);
        assert!(path.contains(&"/usr/local/bin"));
        assert!(path.contains(&"/Users/a/.docker/bin"));
        assert!(path.contains(&"/Applications/Docker.app/Contents/Resources/bin"));
        assert_eq!(path.iter().filter(|p| **p == "/usr/bin").count(), 1);
    }

    #[test]
    fn build_env_posix_defaults_home() {
        let env = build_env(
            Os::Mac,
            &pairs(&[("PATH", "/usr/bin")]),
            Some(Path::new("/h")),
        );
        assert_eq!(env["HOME"], "/h");
    }

    #[test]
    fn build_env_windows_is_case_insensitive() {
        let src = pairs(&[
            ("Path", "C:\\Windows\\system32"),
            ("SystemRoot", "C:\\Windows"),
            ("ProgramFiles", "C:\\Program Files"),
            ("SECRET_TOKEN", "x"),
        ]);
        let env = build_env(Os::Windows, &src, None);
        assert!(env.contains_key("SystemRoot"));
        assert!(!env.contains_key("SECRET_TOKEN"));
        assert!(!env.contains_key("Path"));
        assert_eq!(
            env["PATH"],
            "C:\\Windows\\system32;C:\\Program Files\\Docker\\Docker\\resources\\bin"
        );
    }

    #[test]
    fn which_finds_executables_only() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("docker");
        fs::write(&exe, b"#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                which_in("docker", &dir.path().to_string_lossy(), Os::Mac),
                None
            );
            fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let os = Os::current();
        let path = format!(
            "{}{}{}",
            dir.path().join("missing").display(),
            os.path_list_separator(),
            dir.path().display()
        );
        assert_eq!(which_in("docker", &path, os), Some(exe));
        assert_eq!(which_in("nope", &path, os), None);
    }

    #[test]
    fn whoami_sid_parsing() {
        assert_eq!(
            parse_whoami_sid("\"desktop-1\\krish\",\"S-1-5-21-1-2-3-1001\"\r\n").as_deref(),
            Some("S-1-5-21-1-2-3-1001")
        );
        assert_eq!(parse_whoami_sid("ERROR: nope"), None);
        assert_eq!(parse_whoami_sid("\"a\",\"S-1-5-21-x;rm\""), None);
    }

    #[test]
    fn windows_restrict_uses_icacls_with_sid() {
        let runner = Arc::new(FakeRunner::new());
        runner.respond("whoami.exe", 0, "\"pc\\bob\",\"S-1-5-21-9-9-9-1001\"\r\n");
        runner.respond("icacls.exe", 0, "processed file");
        let mut env = BTreeMap::new();
        env.insert("SystemRoot".to_string(), "D:\\Win".to_string());
        let perms = OwnerOnly::new(Os::Windows, runner.clone(), env);
        perms.restrict(Path::new("C:\\s\\backend\\.env")).unwrap();
        let calls = runner.calls();
        let icacls = calls.iter().find(|c| c[0].ends_with("icacls.exe")).unwrap();
        assert_eq!(
            icacls,
            &vec![
                "D:\\Win\\System32\\icacls.exe".to_string(),
                "C:\\s\\backend\\.env".into(),
                "/inheritance:r".into(),
                "/grant:r".into(),
                "*S-1-5-21-9-9-9-1001:F".into(),
            ]
        );
    }

    #[test]
    fn windows_restrict_falls_back_to_username_and_reports_failure() {
        let runner = Arc::new(FakeRunner::new());
        runner.respond("whoami.exe", 1, "");
        runner.respond("icacls.exe", 5, "");
        let mut env = BTreeMap::new();
        env.insert("USERNAME".to_string(), "bob".to_string());
        env.insert("USERDOMAIN".to_string(), "AzureAD".to_string());
        let perms = OwnerOnly::new(Os::Windows, runner.clone(), env);
        let err = perms.restrict(Path::new("C:\\x")).unwrap_err();
        assert!(err.to_string().contains("icacls"));
        let calls = runner.calls();
        let icacls = calls.iter().find(|c| c[0].ends_with("icacls.exe")).unwrap();
        assert_eq!(icacls[4], "AzureAD\\bob:F");
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_is_0600_and_replaces() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env");
        fs::write(&path, b"old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let perms = OwnerOnly::new(Os::current(), Arc::new(FakeRunner::new()), BTreeMap::new());
        perms.write_atomic(&path, b"new").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn open_docker_desktop_per_os() {
        let runner = FakeRunner::new();
        let mut env = BTreeMap::new();
        env.insert("PROGRAMFILES".to_string(), "C:\\PF".to_string());
        open_docker_desktop(Os::Mac, &runner, &env, &|_| true).unwrap();
        assert_eq!(runner.calls()[0], vec!["/usr/bin/open", "-a", "Docker"]);

        let runner = FakeRunner::new();
        assert_eq!(
            open_docker_desktop(Os::Windows, &runner, &env, &|_| false),
            Err(OpenError::NotInstalled)
        );
        open_docker_desktop(Os::Windows, &runner, &env, &|_| true).unwrap();
        assert_eq!(
            runner.detached(),
            vec![vec![
                "C:\\PF\\Docker\\Docker\\Docker Desktop.exe".to_string()
            ]]
        );
        assert_eq!(
            open_docker_desktop(Os::Linux, &runner, &env, &|_| true),
            Err(OpenError::Unsupported)
        );
    }

    #[test]
    fn open_url_only_web_links() {
        let env = BTreeMap::new();
        assert_eq!(
            open_url_argv(Os::Mac, DOCKER_DESKTOP_URL, &env).unwrap(),
            vec!["/usr/bin/open".to_string(), DOCKER_DESKTOP_URL.into()]
        );
        let win = open_url_argv(Os::Windows, "https://example.com/a", &env).unwrap();
        assert_eq!(win[0], "C:\\Windows\\System32\\rundll32.exe");
        assert_eq!(win[1], "url.dll,FileProtocolHandler");
        for bad in [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "-a Terminal",
            "https://x y",
            "https://x\"&calc",
        ] {
            assert!(open_url_argv(Os::Mac, bad, &env).is_none(), "{bad}");
        }
    }
}

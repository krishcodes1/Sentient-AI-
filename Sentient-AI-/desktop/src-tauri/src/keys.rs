//! Step 2 of setup, "Security keys": generate or validate SECRET_KEY and ENCRYPTION_KEY
//! and write them into the stack's backend/.env, owner-only, keeping a backup of any file
//! it replaces. Key values are never logged, returned or kept after the write.
//!
//! Why it exists: the backend refuses to boot without real keys, and a user should never
//! have to open a terminal or edit .env to get them. The rules match
//! installer/bootstrap.py exactly (the tests replay its outputs from testdata/) so a key
//! one installer accepts is never rejected by the other.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::alphabet;
use base64::engine::general_purpose::{
    GeneralPurpose, GeneralPurposeConfig, URL_SAFE, URL_SAFE_NO_PAD,
};
use base64::engine::DecodePaddingMode;
use base64::Engine as _;
use serde::Serialize;

use crate::platform::OwnerOnly;

pub const SECRET_KEY_MIN: usize = 32;
pub const SECRET_KEY_MAX: usize = 512;
/// Mirrors _PLACEHOLDER_MARKERS in backend/core/config.py.
const PLACEHOLDER_MARKERS: &[&str] = &["replace_me", "changeme", "change-me", "your-secret"];
/// Characters python-dotenv / Compose's env_file parser treat specially.
const ENV_UNSAFE_CHARS: &[char] = &['"', '\'', '`', '\\', '$', '#'];
const KEY_NAMES: [&str; 2] = ["SECRET_KEY", "ENCRYPTION_KEY"];

/// Standard alphabet, `=` padding required where Python's `b64decode(validate=True)`
/// requires it, non-zero trailing bits accepted (Python ignores them too).
const PY_B64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::RequireCanonical),
);

/// Python's `str.isspace()`: Unicode whitespace plus the \x1c-\x1f separators.
fn py_isspace(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// Why `value` can't be SECRET_KEY, or None. Never echoes the value.
pub fn secret_key_problem(value: &str) -> Option<String> {
    if value.is_empty() {
        return Some("Enter a SECRET_KEY.".into());
    }
    if value.chars().any(py_isspace) {
        return Some("SECRET_KEY must not contain spaces or line breaks.".into());
    }
    let len = value.chars().count();
    if len < SECRET_KEY_MIN {
        return Some(format!(
            "SECRET_KEY must be at least {SECRET_KEY_MIN} characters."
        ));
    }
    if len > SECRET_KEY_MAX {
        return Some(format!(
            "SECRET_KEY must be at most {SECRET_KEY_MAX} characters."
        ));
    }
    if value.chars().any(|c| !('\u{21}'..='\u{7e}').contains(&c)) {
        return Some("SECRET_KEY must use plain letters, digits and symbols (ASCII).".into());
    }
    if value.chars().any(|c| ENV_UNSAFE_CHARS.contains(&c)) {
        return Some(
            "SECRET_KEY must not contain quotes, backticks, backslashes, $ or # (.env files treat \
             them specially)."
                .into(),
        );
    }
    let lowered = value.to_ascii_lowercase();
    if PLACEHOLDER_MARKERS.iter().any(|m| lowered.contains(m)) {
        return Some("SECRET_KEY still looks like a placeholder; use a random value.".into());
    }
    let mut unique: Vec<char> = value.chars().collect();
    unique.sort_unstable();
    unique.dedup();
    if unique.len() < 8 {
        return Some("SECRET_KEY is too repetitive; use a random value.".into());
    }
    None
}

/// `[A-Za-z0-9+/_-]+={0,2}` as a full match.
fn looks_base64(value: &str) -> bool {
    let body = value.trim_end_matches('=');
    let pads = value.len() - body.len();
    !body.is_empty()
        && pads <= 2
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'_' | b'-'))
}

/// Why `value` can't be ENCRYPTION_KEY (base64 of exactly 32 bytes), or None.
pub fn encryption_key_problem(value: &str) -> Option<String> {
    if value.is_empty() {
        return Some("Enter an ENCRYPTION_KEY.".into());
    }
    if value.chars().any(py_isspace) {
        return Some("ENCRYPTION_KEY must not contain spaces or line breaks.".into());
    }
    if value.chars().count() > 128 || !looks_base64(value) {
        return Some(
            "ENCRYPTION_KEY must be base64 text (A-Z, a-z, 0-9, + / or - _, with = padding at the \
             end)."
                .into(),
        );
    }
    let standard = value.replace('-', "+").replace('_', "/");
    match PY_B64.decode(standard) {
        Err(_) => Some("ENCRYPTION_KEY isn't valid base64; check the = padding at the end.".into()),
        Ok(raw) if raw.len() != 32 => Some(format!(
            "ENCRYPTION_KEY must decode to exactly 32 bytes (this one decodes to {}).",
            raw.len()
        )),
        Ok(_) => None,
    }
}

#[derive(Debug, thiserror::Error)]
#[error("the system random number generator failed: {0}")]
pub struct RandomError(String);

fn random_bytes<const N: usize>() -> Result<[u8; N], RandomError> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).map_err(|e| RandomError(e.to_string()))?;
    Ok(buf)
}

/// 48 CSPRNG bytes, URL-safe base64 without padding: 64 characters (as
/// `secrets.token_urlsafe(48)`). Redrawn in the astronomically unlikely case it trips a
/// validation rule.
pub fn generate_secret_key() -> Result<String, RandomError> {
    loop {
        let key = URL_SAFE_NO_PAD.encode(random_bytes::<48>()?);
        if secret_key_problem(&key).is_none() {
            return Ok(key);
        }
    }
}

/// 32 CSPRNG bytes, URL-safe base64 with padding: 44 characters (the backend decodes it
/// with `base64.urlsafe_b64decode`, which requires the padding).
pub fn generate_encryption_key() -> Result<String, RandomError> {
    Ok(URL_SAFE.encode(random_bytes::<32>()?))
}

// ── .env text ────────────────────────────────────────────────────────────────

struct KeyLine<'a> {
    indent: &'a [u8],
    export: &'a [u8],
    name: &'static str,
    value: &'a [u8],
}

fn skip_blanks(s: &[u8]) -> usize {
    s.iter().take_while(|b| matches!(b, b' ' | b'\t')).count()
}

/// Match `^[ \t]*(export[ \t]+)?(SECRET_KEY|ENCRYPTION_KEY)[ \t]*=(.*)$` on one line.
fn parse_key_line(body: &[u8]) -> Option<KeyLine<'_>> {
    let indent_len = skip_blanks(body);
    let (indent, rest) = body.split_at(indent_len);
    let (export, rest) = match rest.strip_prefix(b"export") {
        Some(after) if skip_blanks(after) > 0 => {
            let len = 6 + skip_blanks(after);
            rest.split_at(len)
        }
        _ => (&rest[..0], rest),
    };
    let name = KEY_NAMES
        .into_iter()
        .find(|n| rest.starts_with(n.as_bytes()))?;
    let rest = &rest[name.len()..];
    let rest = &rest[skip_blanks(rest)..];
    let value = rest.strip_prefix(b"=")?;
    Some(KeyLine {
        indent,
        export,
        name,
        value,
    })
}

/// Replace the `NAME=` lines for each key in `values`; keep every other byte as it was.
/// Keys with no line are appended at the end (bootstrap.py's replace_keys).
pub fn replace_keys(text: &[u8], values: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() + 160);
    let mut seen: Vec<&str> = Vec::new();
    for (i, part) in text.split(|b| *b == b'\n').enumerate() {
        if i > 0 {
            out.push(b'\n');
        }
        let (body, ending): (&[u8], &[u8]) = match part.strip_suffix(b"\r") {
            Some(body) => (body, b"\r"),
            None => (part, b""),
        };
        let replacement = parse_key_line(body).and_then(|line| {
            values
                .iter()
                .find(|(name, _)| *name == line.name)
                .map(|(name, value)| (line, *name, *value))
        });
        match replacement {
            Some((line, name, value)) => {
                out.extend_from_slice(line.indent);
                out.extend_from_slice(line.export);
                out.extend_from_slice(name.as_bytes());
                out.push(b'=');
                out.extend_from_slice(value.as_bytes());
                out.extend_from_slice(ending);
                if !seen.contains(&name) {
                    seen.push(name);
                }
            }
            None => out.extend_from_slice(part),
        }
    }
    let missing: Vec<&(&str, &str)> = values.iter().filter(|(n, _)| !seen.contains(n)).collect();
    if !missing.is_empty() {
        if !out.is_empty() && !out.ends_with(b"\n") {
            out.push(b'\n');
        }
        for (name, value) in missing {
            out.extend_from_slice(format!("{name}={value}\n").as_bytes());
        }
    }
    out
}

/// A `.env` value as python-dotenv reads it: quoted, or up to an inline ` #` comment.
fn env_value(raw: &[u8]) -> String {
    let raw = String::from_utf8_lossy(raw);
    let value = raw.trim();
    if let Some(quote) = value.chars().next().filter(|c| *c == '"' || *c == '\'') {
        let inner = &value[1..];
        return match inner.find(quote) {
            Some(end) => inner[..end].to_string(),
            None => inner.to_string(),
        };
    }
    match value.find(" #") {
        Some(idx) => value[..idx].trim_end().to_string(),
        None => value.to_string(),
    }
}

fn looks_real(name: &str, value: &str) -> bool {
    if name == "SECRET_KEY" {
        let stripped = value.trim();
        let lowered = stripped.to_lowercase();
        stripped.chars().count() >= SECRET_KEY_MIN
            && !PLACEHOLDER_MARKERS.iter().any(|m| lowered.contains(m))
    } else {
        encryption_key_problem(value).is_none()
    }
}

/// Whether each key in a .env looks real. Values never leave this function.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct KeyStatus {
    pub secret_key: bool,
    pub encryption_key: bool,
}

impl KeyStatus {
    pub fn all_set(self) -> bool {
        self.secret_key && self.encryption_key
    }
}

pub fn env_key_status(env_path: &Path) -> KeyStatus {
    let mut status = KeyStatus::default();
    let Ok(bytes) = fs::read(env_path) else {
        return status;
    };
    for line in bytes.split(|b| *b == b'\n') {
        let body = line.strip_suffix(b"\r").unwrap_or(line);
        if let Some(parsed) = parse_key_line(body) {
            // Last assignment wins, as in python-dotenv.
            let real = looks_real(parsed.name, &env_value(parsed.value));
            match parsed.name {
                "SECRET_KEY" => status.secret_key = real,
                _ => status.encryption_key = real,
            }
        }
    }
    status
}

// ── Writing backend/.env ─────────────────────────────────────────────────────

/// How to get the keys. `Debug` never prints them.
pub enum KeyMode {
    Generate,
    Custom {
        secret_key: String,
        encryption_key: String,
    },
}

impl fmt::Debug for KeyMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyMode::Generate => f.write_str("Generate"),
            KeyMode::Custom { .. } => f.write_str("Custom { <redacted> }"),
        }
    }
}

impl KeyMode {
    fn label(&self) -> &'static str {
        match self {
            KeyMode::Generate => "generate",
            KeyMode::Custom { .. } => "custom",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KeyWriteError {
    #[error("the keys are not valid")]
    Invalid(BTreeMap<String, String>),
    #[error("backend/.env already exists")]
    Exists,
    #[error("the bundled backend/.env.example is missing")]
    NoExample,
    #[error("could not write backend/.env ({0})")]
    WriteFailed(String),
    #[error(transparent)]
    Random(#[from] RandomError),
}

impl KeyWriteError {
    pub fn reason(&self) -> &'static str {
        match self {
            KeyWriteError::Invalid(_) => "invalid",
            KeyWriteError::Exists => "exists",
            KeyWriteError::NoExample => "no_example",
            KeyWriteError::WriteFailed(_) => "write_failed",
            KeyWriteError::Random(_) => "random_failed",
        }
    }
}

fn io_reason(err: &io::Error) -> String {
    // The OS message only; paths and contents stay out of it.
    let kind = err.kind();
    if kind == io::ErrorKind::Other {
        err.to_string()
    } else {
        format!("{kind}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WriteOutcome {
    pub mode: &'static str,
    pub replaced_existing: bool,
    /// e.g. "backend/.env.bak-20260924-181500"
    pub backup: Option<String>,
}

/// What the setup window gets back from a key write: never the keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WriteReport {
    pub ok: bool,
    pub reason: Option<String>,
    pub errors: Option<BTreeMap<String, String>>,
    pub mode: Option<String>,
    pub replaced_existing: bool,
    pub backup: Option<String>,
    pub message: Option<String>,
}

impl From<Result<WriteOutcome, KeyWriteError>> for WriteReport {
    fn from(result: Result<WriteOutcome, KeyWriteError>) -> Self {
        match result {
            Ok(outcome) => WriteReport {
                ok: true,
                reason: None,
                errors: None,
                mode: Some(outcome.mode.into()),
                replaced_existing: outcome.replaced_existing,
                backup: outcome.backup,
                message: None,
            },
            Err(err) => WriteReport {
                ok: false,
                reason: Some(err.reason().into()),
                message: Some(err.to_string()),
                errors: match err {
                    KeyWriteError::Invalid(errors) => Some(errors),
                    _ => None,
                },
                mode: None,
                replaced_existing: false,
                backup: None,
            },
        }
    }
}

/// `YYYYmmdd-HHMMSS` in UTC.
fn utc_stamp(time: SystemTime) -> String {
    let secs = time
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}{month:02}{day:02}-{:02}{:02}{:02}",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Creates or updates backend/.env with SECRET_KEY and ENCRYPTION_KEY.
pub struct KeyWriter {
    pub env_path: PathBuf,
    /// The bundled backend/.env.example, used when backend/.env does not exist yet.
    pub example_path: PathBuf,
    perms: OwnerOnly,
    clock: fn() -> SystemTime,
    lock: Mutex<()>,
}

impl KeyWriter {
    pub fn new(env_path: PathBuf, example_path: PathBuf, perms: OwnerOnly) -> Self {
        Self {
            env_path,
            example_path,
            perms,
            clock: SystemTime::now,
            lock: Mutex::new(()),
        }
    }

    pub fn with_clock(mut self, clock: fn() -> SystemTime) -> Self {
        self.clock = clock;
        self
    }

    pub fn status(&self) -> KeyStatus {
        env_key_status(&self.env_path)
    }

    pub fn write(&self, mode: KeyMode, overwrite: bool) -> Result<WriteOutcome, KeyWriteError> {
        let label = mode.label();
        let (secret_key, encryption_key) = match mode {
            KeyMode::Generate => (generate_secret_key()?, generate_encryption_key()?),
            KeyMode::Custom {
                secret_key,
                encryption_key,
            } => {
                let mut errors = BTreeMap::new();
                if let Some(problem) = secret_key_problem(&secret_key) {
                    errors.insert("secret_key".to_string(), problem);
                }
                if let Some(problem) = encryption_key_problem(&encryption_key) {
                    errors.insert("encryption_key".to_string(), problem);
                }
                if !errors.is_empty() {
                    return Err(KeyWriteError::Invalid(errors));
                }
                (secret_key, encryption_key)
            }
        };

        let _guard = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        let exists = self.env_path.exists();
        if exists && !overwrite {
            return Err(KeyWriteError::Exists);
        }
        let fail = |e: io::Error| KeyWriteError::WriteFailed(io_reason(&e));
        let mut backup = None;
        let base = if exists {
            let original = fs::read(&self.env_path).map_err(fail)?;
            backup = Some(self.backup(&original).map_err(fail)?);
            original
        } else if self.example_path.is_file() {
            fs::read(&self.example_path).map_err(fail)?
        } else {
            return Err(KeyWriteError::NoExample);
        };
        let updated = replace_keys(
            &base,
            &[
                ("SECRET_KEY", secret_key.as_str()),
                ("ENCRYPTION_KEY", encryption_key.as_str()),
            ],
        );
        if let Some(dir) = self.env_path.parent() {
            fs::create_dir_all(dir).map_err(fail)?;
        }
        self.perms
            .write_atomic(&self.env_path, &updated)
            .map_err(fail)?;
        Ok(WriteOutcome {
            mode: label,
            replaced_existing: exists,
            backup: backup.map(|name| format!("backend/{name}")),
        })
    }

    fn backup(&self, data: &[u8]) -> io::Result<String> {
        let stamp = utc_stamp((self.clock)());
        for attempt in 0..100 {
            let suffix = if attempt == 0 {
                String::new()
            } else {
                format!("-{attempt}")
            };
            let name = format!(".env.bak-{stamp}{suffix}");
            match self
                .perms
                .create_new(&self.env_path.with_file_name(&name), data)
            {
                Ok(()) => return Ok(name),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::other("too many backups this second"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::Os;
    use crate::test_support::{owner_only, runner_with_account, FakeRunner};
    use std::sync::Arc;

    const EXAMPLE: &str = "# header\nDATABASE_URL=postgresql://x\nSECRET_KEY=REPLACE_ME_run_the_command_above\nENCRYPTION_KEY=REPLACE_ME_run_the_command_above\nTAIL=1\n";

    fn writer(dir: &Path) -> KeyWriter {
        let example = dir.join("bundle/backend/.env.example");
        fs::create_dir_all(example.parent().unwrap()).unwrap();
        fs::write(&example, EXAMPLE).unwrap();
        let perms = owner_only(runner_with_account());
        KeyWriter::new(dir.join("stack/1.0.0/backend/.env"), example, perms)
            .with_clock(|| UNIX_EPOCH + std::time::Duration::from_secs(1_790_000_000))
    }

    fn good_secret() -> String {
        generate_secret_key().unwrap()
    }

    #[test]
    fn generated_keys_have_the_right_shape() {
        for _ in 0..50 {
            let s = generate_secret_key().unwrap();
            assert_eq!(s.len(), 64);
            assert!(s
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
            assert_eq!(secret_key_problem(&s), None);
            let e = generate_encryption_key().unwrap();
            assert_eq!(e.len(), 44);
            assert!(e.ends_with('='));
            assert_eq!(encryption_key_problem(&e), None);
            assert_eq!(URL_SAFE.decode(&e).unwrap().len(), 32);
        }
        assert_ne!(
            generate_secret_key().unwrap(),
            generate_secret_key().unwrap()
        );
    }

    #[derive(serde::Deserialize)]
    struct Cases {
        enc: Vec<(String, Option<String>)>,
        sec: Vec<(String, Option<String>)>,
    }

    /// testdata/bootstrap_key_cases.json holds bootstrap.py's own answers
    /// (encryption_key_problem / secret_key_problem) for each input.
    #[test]
    fn validation_matches_bootstrap_py() {
        let cases: Cases =
            serde_json::from_str(include_str!("../testdata/bootstrap_key_cases.json")).unwrap();
        for (input, expected) in cases.enc {
            assert_eq!(encryption_key_problem(&input), expected, "enc {input:?}");
        }
        for (input, expected) in cases.sec {
            assert_eq!(secret_key_problem(&input), expected, "sec {input:?}");
        }
    }

    #[derive(serde::Deserialize)]
    struct ReplaceCases {
        values: BTreeMap<String, String>,
        cases: Vec<(String, String)>,
    }

    /// testdata/bootstrap_replace_keys_cases.json holds bootstrap.py's replace_keys output.
    #[test]
    fn replace_keys_matches_bootstrap_py() {
        let data: ReplaceCases = serde_json::from_str(include_str!(
            "../testdata/bootstrap_replace_keys_cases.json"
        ))
        .unwrap();
        let values = [
            ("SECRET_KEY", data.values["SECRET_KEY"].as_str()),
            ("ENCRYPTION_KEY", data.values["ENCRYPTION_KEY"].as_str()),
        ];
        for (input, expected) in data.cases {
            let got = replace_keys(input.as_bytes(), &values);
            assert_eq!(String::from_utf8(got).unwrap(), expected, "input {input:?}");
        }
    }

    #[test]
    fn replace_keys_keeps_non_utf8_bytes() {
        let input = b"X=\xff\xfe\nSECRET_KEY=old\n";
        let out = replace_keys(input, &[("SECRET_KEY", "new")]);
        assert_eq!(out, b"X=\xff\xfe\nSECRET_KEY=new\n");
    }

    #[test]
    fn key_status_reads_only_booleans() {
        let dir = tempfile::tempdir().unwrap();
        let env = dir.path().join(".env");
        assert_eq!(env_key_status(&env), KeyStatus::default());
        fs::write(&env, EXAMPLE).unwrap();
        assert!(!env_key_status(&env).all_set());
        let text = format!(
            "SECRET_KEY=\"{}\" # quoted\nexport ENCRYPTION_KEY={} # c\n",
            good_secret(),
            generate_encryption_key().unwrap()
        );
        fs::write(&env, text).unwrap();
        assert!(env_key_status(&env).all_set());
        // Last assignment wins.
        fs::write(
            &env,
            format!("SECRET_KEY={}\nSECRET_KEY=changeme\n", good_secret()),
        )
        .unwrap();
        assert!(!env_key_status(&env).secret_key);
    }

    #[test]
    fn write_generate_from_example_keeps_other_lines() {
        let dir = tempfile::tempdir().unwrap();
        let w = writer(dir.path());
        let outcome = w.write(KeyMode::Generate, false).unwrap();
        assert_eq!(
            outcome,
            WriteOutcome {
                mode: "generate",
                replaced_existing: false,
                backup: None
            }
        );
        let text = fs::read_to_string(&w.env_path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "# header");
        assert_eq!(lines[1], "DATABASE_URL=postgresql://x");
        assert!(lines[2].starts_with("SECRET_KEY=") && lines[2].len() == 11 + 64);
        assert!(lines[3].starts_with("ENCRYPTION_KEY=") && lines[3].len() == 15 + 44);
        assert_eq!(lines[4], "TAIL=1");
        assert_eq!(lines.len(), 5);
        assert!(w.status().all_set());
    }

    #[test]
    fn write_refuses_existing_without_overwrite_then_backs_up() {
        let dir = tempfile::tempdir().unwrap();
        let w = writer(dir.path());
        w.write(KeyMode::Generate, false).unwrap();
        let first = fs::read(&w.env_path).unwrap();
        assert!(matches!(
            w.write(KeyMode::Generate, false),
            Err(KeyWriteError::Exists)
        ));
        assert_eq!(fs::read(&w.env_path).unwrap(), first);

        let outcome = w.write(KeyMode::Generate, true).unwrap();
        assert!(outcome.replaced_existing);
        let backup = outcome.backup.unwrap();
        assert_eq!(backup, "backend/.env.bak-20260921-141320");
        let backup_path = w.env_path.with_file_name(".env.bak-20260921-141320");
        assert_eq!(fs::read(&backup_path).unwrap(), first);
        assert_ne!(fs::read(&w.env_path).unwrap(), first);
        // Same second again: a numbered backup, never an overwrite.
        let again = w.write(KeyMode::Generate, true).unwrap();
        assert_eq!(again.backup.unwrap(), "backend/.env.bak-20260921-141320-1");
    }

    #[test]
    fn write_custom_validates_and_never_echoes() {
        let dir = tempfile::tempdir().unwrap();
        let w = writer(dir.path());
        let bad = KeyMode::Custom {
            secret_key: "changeme-changeme-changeme-changeme".into(),
            encryption_key: "A".repeat(43),
        };
        let report = WriteReport::from(w.write(bad, false));
        assert!(!report.ok);
        assert_eq!(report.reason.as_deref(), Some("invalid"));
        let errors = report.errors.unwrap();
        assert!(errors["secret_key"].contains("placeholder"));
        assert!(errors["encryption_key"].contains("padding"));
        assert!(!w.env_path.exists());

        let secret = good_secret();
        let enc = generate_encryption_key().unwrap();
        let mode = KeyMode::Custom {
            secret_key: secret.clone(),
            encryption_key: enc.clone(),
        };
        assert!(!format!("{mode:?}").contains(&secret));
        let report = WriteReport::from(w.write(mode, false));
        assert!(report.ok);
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains(&secret) && !json.contains(&enc));
        let text = fs::read_to_string(&w.env_path).unwrap();
        assert!(text.contains(&format!("SECRET_KEY={secret}\n")));
        assert!(text.contains(&format!("ENCRYPTION_KEY={enc}\n")));
    }

    #[test]
    fn write_without_example_fails_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let w = writer(dir.path());
        fs::remove_file(&w.example_path).unwrap();
        let report = WriteReport::from(w.write(KeyMode::Generate, false));
        assert_eq!(report.reason.as_deref(), Some("no_example"));
    }

    #[cfg(unix)]
    #[test]
    fn env_and_backup_are_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let w = writer(dir.path());
        w.write(KeyMode::Generate, false).unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&w.env_path), 0o600);
        fs::set_permissions(&w.env_path, fs::Permissions::from_mode(0o644)).unwrap();
        let backup = w.write(KeyMode::Generate, true).unwrap().backup.unwrap();
        assert_eq!(mode(&w.env_path), 0o600);
        let backup_path = w
            .env_path
            .parent()
            .unwrap()
            .join(backup.trim_start_matches("backend/"));
        assert_eq!(mode(&backup_path), 0o600);
    }

    #[test]
    fn windows_write_applies_acl_before_writing() {
        let dir = tempfile::tempdir().unwrap();
        let runner = Arc::new(FakeRunner::new());
        runner.respond("whoami.exe", 0, "\"pc\\bob\",\"S-1-5-21-1-2-3-1001\"");
        let perms = OwnerOnly::new(Os::Windows, runner.clone(), BTreeMap::new());
        let example = dir.path().join(".env.example");
        fs::write(&example, EXAMPLE).unwrap();
        let w = KeyWriter::new(dir.path().join("backend/.env"), example, perms);
        w.write(KeyMode::Generate, false).unwrap();
        let icacls: Vec<Vec<String>> = runner
            .calls()
            .into_iter()
            .filter(|c| c[0].ends_with("icacls.exe"))
            .collect();
        assert_eq!(icacls.len(), 1);
        assert!(
            icacls[0][1].contains(".env.tmp-"),
            "ACL goes on the temp file before rename"
        );
        assert_eq!(
            &icacls[0][2..],
            &["/inheritance:r", "/grant:r", "*S-1-5-21-1-2-3-1001:F"]
        );
    }

    #[test]
    fn stamp_is_utc() {
        assert_eq!(utc_stamp(UNIX_EPOCH), "19700101-000000");
        assert_eq!(
            utc_stamp(UNIX_EPOCH + std::time::Duration::from_secs(951_782_400)),
            "20000229-000000"
        );
    }
}

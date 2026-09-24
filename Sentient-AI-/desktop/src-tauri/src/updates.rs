//! "Check for updates" (v1): asks GitHub Releases for the newest desktop build, compares it
//! with the running version and offers the download page — from the tray (a native dialog)
//! and from the status screen (the `check_updates` command returns an `UpdateInfo`).
//!
//! Why not an in-app updater yet: Tauri's updater needs its own signing key, which the owner
//! creates and stores as a GitHub secret (planned for v1.1). Until then an update is a normal
//! download-and-install over the old version.

use std::time::Duration;

use semver::Version;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Runtime};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
use tauri_plugin_opener::OpenerExt;

const RELEASES_API: &str =
    "https://api.github.com/repos/krishcodes1/Sentient-AI-/releases?per_page=30";
const RELEASES_PAGE: &str = "https://github.com/krishcodes1/Sentient-AI-/releases";
/// Desktop releases are tagged `desktop-v<semver>` (see .github/workflows/desktop.yml).
const TAG_PREFIX: &str = "desktop-v";

#[derive(Debug, Deserialize)]
pub struct Release {
    pub tag_name: String,
    pub html_url: String,
    #[serde(default)]
    pub draft: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    UpToDate,
    Available { version: Version, url: String },
}

/// The newest published desktop release. Beta builds are GitHub pre-releases, so those
/// count; drafts (and any non-desktop tags) do not.
pub fn newest(releases: &[Release]) -> Option<(Version, &Release)> {
    releases
        .iter()
        .filter(|r| !r.draft)
        .filter_map(|r| {
            let version = Version::parse(r.tag_name.strip_prefix(TAG_PREFIX)?).ok()?;
            Some((version, r))
        })
        .max_by(|a, b| a.0.cmp(&b.0))
}

/// The release's page when it is a plain https page on github.com, else the releases list.
/// The URL comes from a network response and is handed to the system opener, so nothing
/// else (another scheme, another host, a look-alike domain) is ever opened.
fn release_page(release: &Release) -> String {
    let url = release.html_url.as_str();
    let safe = url.starts_with("https://github.com/")
        && url.len() <= 2048
        && !url.chars().any(|c| c.is_control() || c.is_whitespace());
    if safe {
        url.to_string()
    } else {
        RELEASES_PAGE.to_string()
    }
}

pub fn compare(current: &Version, releases: &[Release]) -> Outcome {
    match newest(releases) {
        Some((version, release)) if version > *current => Outcome::Available {
            version,
            url: release_page(release),
        },
        _ => Outcome::UpToDate,
    }
}

/// What the status screen shows (`check_updates`; desktop/ui/src/bridge.ts `UpdateInfo`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpdateInfo {
    /// The newest published desktop version, if GitHub lists any.
    pub latest: Option<String>,
    /// Its release page (or the releases list when there is none).
    pub url: String,
    /// `latest` is newer than the running app.
    pub newer: bool,
}

pub fn update_info(current: &Version, releases: &[Release]) -> UpdateInfo {
    match newest(releases) {
        Some((version, release)) => UpdateInfo {
            newer: version > *current,
            latest: Some(version.to_string()),
            url: release_page(release),
        },
        None => UpdateInfo {
            latest: None,
            url: RELEASES_PAGE.to_string(),
            newer: false,
        },
    }
}

/// Ask GitHub now (blocking, up to 15 s). Call it off the main thread.
pub fn check_now(current: &Version) -> Result<UpdateInfo, String> {
    fetch_releases().map(|releases| update_info(current, &releases))
}

fn fetch_releases() -> Result<Vec<Release>, String> {
    let body = ureq::get(RELEASES_API)
        .set("Accept", "application/vnd.github+json")
        .set("User-Agent", "crawler-ai-desktop")
        .timeout(Duration::from_secs(15))
        .call()
        .map_err(|e| e.to_string())?
        .into_string()
        .map_err(|e| e.to_string())?;
    serde_json::from_str(&body).map_err(|e| e.to_string())
}

/// Runs the check off the main thread and answers with a native dialog.
pub fn check_in_background<R: Runtime>(app: &AppHandle<R>) {
    let app = app.clone();
    std::thread::spawn(move || {
        let current = app.package_info().version.clone();
        let outcome = fetch_releases().map(|releases| compare(&current, &releases));
        report(&app, &current, outcome);
    });
}

fn report<R: Runtime>(app: &AppHandle<R>, current: &Version, outcome: Result<Outcome, String>) {
    let (title, message, url) = match outcome {
        Ok(Outcome::UpToDate) => {
            app.dialog()
                .message(format!(
                    "You have the latest version of Crawler AI ({current})."
                ))
                .title("Crawler AI is up to date")
                .kind(MessageDialogKind::Info)
                .show(|_| {});
            return;
        }
        Ok(Outcome::Available { version, url }) => (
            "Update available",
            format!(
                "Crawler AI {version} is available (you have {current}).\n\n\
                 Download it and install it over this version."
            ),
            url,
        ),
        Err(err) => (
            "Couldn't check for updates",
            format!("GitHub could not be reached ({err}).\n\nOpen the releases page instead?"),
            RELEASES_PAGE.to_string(),
        ),
    };
    let opener = app.clone();
    app.dialog()
        .message(message)
        .title(title)
        .kind(MessageDialogKind::Info)
        .buttons(MessageDialogButtons::OkCancelCustom(
            "Open download page".into(),
            "Later".into(),
        ))
        .show(move |open| {
            if open {
                let _ = opener.opener().open_url(url, None::<&str>);
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(tag: &str, draft: bool) -> Release {
        Release {
            tag_name: tag.into(),
            html_url: format!("https://github.com/x/y/releases/tag/{tag}"),
            draft,
        }
    }

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    #[test]
    fn picks_the_highest_desktop_tag_not_the_first() {
        let releases = [
            release("desktop-v0.1.1", false),
            release("desktop-v0.2.0-beta.1", false),
            release("desktop-v0.1.10", false),
            release("v9.9.9", false),        // not a desktop release
            release("desktop-v1.0.0", true), // draft: not published yet
            release("desktop-vnext", false),
        ];
        let (version, r) = newest(&releases).unwrap();
        assert_eq!(version, v("0.2.0-beta.1"));
        assert_eq!(r.tag_name, "desktop-v0.2.0-beta.1");
    }

    #[test]
    fn offers_a_newer_release() {
        let releases = [release("desktop-v0.2.0", false)];
        assert_eq!(
            compare(&v("0.1.0"), &releases),
            Outcome::Available {
                version: v("0.2.0"),
                url: "https://github.com/x/y/releases/tag/desktop-v0.2.0".into()
            }
        );
    }

    #[test]
    fn same_older_or_prerelease_of_current_is_up_to_date() {
        for tag in ["desktop-v0.1.0", "desktop-v0.0.9", "desktop-v0.1.0-beta.2"] {
            assert_eq!(
                compare(&v("0.1.0"), &[release(tag, false)]),
                Outcome::UpToDate,
                "{tag}"
            );
        }
        assert_eq!(compare(&v("0.1.0"), &[]), Outcome::UpToDate);
    }

    #[test]
    fn update_info_for_the_status_screen() {
        let releases = [
            release("desktop-v0.2.0", false),
            release("desktop-v0.1.0", false),
        ];
        assert_eq!(
            update_info(&v("0.1.0"), &releases),
            UpdateInfo {
                latest: Some("0.2.0".into()),
                url: "https://github.com/x/y/releases/tag/desktop-v0.2.0".into(),
                newer: true,
            }
        );
        let same = update_info(&v("0.2.0"), &releases);
        assert!(!same.newer);
        assert_eq!(same.latest.as_deref(), Some("0.2.0"));
        let none = update_info(&v("0.1.0"), &[]);
        assert_eq!(none.latest, None);
        assert_eq!(none.url, RELEASES_PAGE);
        assert!(!none.newer);
    }

    /// The page we open comes from a network response: anything but a github.com https
    /// page (another scheme, another host, a look-alike) falls back to the releases list.
    #[test]
    fn only_github_release_pages_are_opened() {
        for bad in [
            "file:///Applications/Calculator.app",
            "javascript:alert(1)",
            "http://github.com/x/y/releases/tag/desktop-v0.2.0",
            "https://github.com.evil.example/x",
            "https://evil.example/https://github.com/",
            "https://github.com/x/y releases",
            "",
        ] {
            let releases = [Release {
                tag_name: "desktop-v0.2.0".into(),
                html_url: bad.into(),
                draft: false,
            }];
            assert_eq!(
                update_info(&v("0.1.0"), &releases).url,
                RELEASES_PAGE,
                "{bad:?}"
            );
            assert_eq!(
                compare(&v("0.1.0"), &releases),
                Outcome::Available {
                    version: v("0.2.0"),
                    url: RELEASES_PAGE.into()
                },
                "{bad:?}"
            );
        }
    }

    #[test]
    fn parses_the_github_api_shape() {
        let body = r#"[{"tag_name":"desktop-v0.3.0","html_url":"https://github.com/o/r/releases/tag/desktop-v0.3.0","draft":false,"prerelease":true,"assets":[]}]"#;
        let releases: Vec<Release> = serde_json::from_str(body).unwrap();
        assert_eq!(newest(&releases).unwrap().0, v("0.3.0"));
    }
}

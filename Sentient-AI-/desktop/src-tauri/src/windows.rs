//! The app's two windows and where each may navigate.
//!
//! Two windows with two trust levels:
//! - "setup" loads the bundled setup/status UI (ui/dist) and is the only window with IPC
//!   (capabilities/setup.json). It runs the first-run wizard and, later, the status screen.
//! - "crawler" loads Crawler AI itself from http://localhost:3000 and is in no capability, so
//!   the web app can never start/stop the stack or read files.
//!
//! Why it lives in the library: the setup UI's "Open" command (commands.rs) and the app shell
//! (main.rs, tray.rs) must open the same windows the same way. Links that leave a window's own
//! content open in the default browser, never inside the app.

use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use tauri::webview::NewWindowResponse;
use tauri::{AppHandle, Manager, Runtime, Url, WebviewUrl, WebviewWindow, WebviewWindowBuilder};
use tauri_plugin_opener::OpenerExt;

/// Label of the bundled setup/status window — the only one granted IPC.
pub const SETUP_WINDOW: &str = "setup";
/// Label of the Crawler AI window — deliberately in no capability.
pub const CRAWLER_WINDOW: &str = "crawler";
/// Where the stack's frontend answers (docker/docker-compose.yml publishes 3000).
pub const CRAWLER_URL: &str = "http://localhost:3000/";
const CRAWLER_PORT: u16 = 3000;

/// Opens whatever "the app" means right now: Crawler AI when it is installed and answering,
/// otherwise the setup/status window (first-run wizard, or Start when the stack is down).
/// Used at launch, by a second launch, the Dock icon and the tray.
pub fn show_main_window<R: Runtime>(app: &AppHandle<R>) {
    let result = if crate::commands::is_installed(app) && crawler_is_up() {
        open_crawler_window(app)
    } else {
        show_setup_window(app)
    };
    if let Err(err) = result {
        eprintln!("crawler-ai: could not open a window: {err}");
    }
}

/// Shows (creating on first use) the bundled setup/status window.
pub fn show_setup_window<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<()> {
    if let Some(window) = app.get_webview_window(SETUP_WINDOW) {
        return reveal(&window);
    }
    // `tauri dev` serves the UI from devUrl. A bundled app (release, or `tauri build --debug`)
    // embeds the UI and never accepts it: whatever listens on that port then is not ours.
    let dev_url = if tauri::is_dev() {
        app.config().build.dev_url.clone()
    } else {
        None
    };
    let nav_app = app.clone();
    let popup_app = app.clone();
    let window = WebviewWindowBuilder::new(app, SETUP_WINDOW, WebviewUrl::App("index.html".into()))
        .title("Crawler AI")
        .inner_size(760.0, 680.0)
        .min_inner_size(640.0, 560.0)
        .center()
        .on_navigation(move |url| follow(&nav_app, url, setup_nav(url, dev_url.as_ref())))
        .on_new_window(move |url, _| open_popup_in_browser(&popup_app, &url))
        .build()?;
    reveal(&window)
}

/// Shows (creating on first use) the Crawler AI window and hides the setup/status window —
/// the app window "becomes" Crawler AI. Call it from an `async` command: building a window in
/// a sync command can deadlock on Windows.
pub fn open_crawler_window<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<()> {
    let window = match app.get_webview_window(CRAWLER_WINDOW) {
        Some(window) => window,
        None => {
            let url: Url = CRAWLER_URL.parse().expect("CRAWLER_URL is a valid URL");
            let nav_app = app.clone();
            let popup_app = app.clone();
            WebviewWindowBuilder::new(app, CRAWLER_WINDOW, WebviewUrl::External(url))
                .title("Crawler AI")
                .inner_size(1280.0, 820.0)
                .min_inner_size(900.0, 600.0)
                .center()
                .on_navigation(move |url| follow(&nav_app, url, crawler_nav(url)))
                .on_new_window(move |url, _| open_popup_in_browser(&popup_app, &url))
                .build()?
        }
    };
    reveal(&window)?;
    if let Some(setup) = app.get_webview_window(SETUP_WINDOW) {
        setup.hide()?;
    }
    Ok(())
}

fn reveal<R: Runtime>(window: &WebviewWindow<R>) -> tauri::Result<()> {
    window.show()?;
    window.unminimize()?;
    window.set_focus()
}

/// Is the stack's frontend accepting connections? A quick local TCP probe, so launching the
/// app never shows Crawler AI's window over a connection error.
fn crawler_is_up() -> bool {
    let addr = SocketAddr::from(([127, 0, 0, 1], CRAWLER_PORT));
    TcpStream::connect_timeout(&addr, Duration::from_millis(400)).is_ok()
}

/// What a window does with a navigation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Nav {
    /// Load it in the window.
    Stay,
    /// Cancel it and hand the URL to the default browser / mail app.
    OpenInBrowser,
    /// Cancel it.
    Block,
}

fn follow<R: Runtime>(app: &AppHandle<R>, url: &Url, nav: Nav) -> bool {
    match nav {
        Nav::Stay => true,
        Nav::OpenInBrowser => {
            let _ = app.opener().open_url(url.as_str(), None::<&str>);
            false
        }
        Nav::Block => false,
    }
}

/// `target="_blank"` links and `window.open` never create app windows: web links go to the
/// default browser, anything else is dropped.
fn open_popup_in_browser<R: Runtime>(app: &AppHandle<R>, url: &Url) -> NewWindowResponse<R> {
    if external_nav(url) == Nav::OpenInBrowser {
        let _ = app.opener().open_url(url.as_str(), None::<&str>);
    }
    NewWindowResponse::Deny
}

/// Navigations inside the Crawler AI window: Crawler AI itself stays, the rest leaves the app.
fn crawler_nav(url: &Url) -> Nav {
    let is_crawler = url.scheme() == "http"
        && matches!(url.host_str(), Some("localhost" | "127.0.0.1"))
        && url.port_or_known_default() == Some(CRAWLER_PORT);
    if is_crawler {
        Nav::Stay
    } else {
        external_nav(url)
    }
}

/// Navigations inside the setup window: only the bundled UI (or, in dev, the dev server).
fn setup_nav(url: &Url, dev_url: Option<&Url>) -> Nav {
    let bundled = match url.scheme() {
        // macOS / Linux serve the bundle from tauri://localhost, Windows from http(s)://tauri.localhost.
        "tauri" => url.host_str() == Some("localhost"),
        "http" | "https" => url.host_str() == Some("tauri.localhost"),
        _ => false,
    };
    let dev_server = dev_url.is_some_and(|dev| same_origin(dev, url));
    if bundled || dev_server {
        Nav::Stay
    } else {
        external_nav(url)
    }
}

/// A URL that is not the window's own content: blank frames and blob downloads stay, web and
/// mail links go to the system, anything else (file:, javascript:, custom schemes) is dropped.
fn external_nav(url: &Url) -> Nav {
    match url.scheme() {
        "about" | "blob" => Nav::Stay,
        "http" | "https" | "mailto" => Nav::OpenInBrowser,
        _ => Nav::Block,
    }
}

fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> Url {
        s.parse().unwrap()
    }

    #[test]
    fn crawler_url_is_the_stack_frontend() {
        let u = url(CRAWLER_URL);
        assert_eq!(u.port_or_known_default(), Some(CRAWLER_PORT));
        assert_eq!(crawler_nav(&u), Nav::Stay);
    }

    #[test]
    fn crawler_window_keeps_crawler_pages() {
        for u in [
            "http://localhost:3000/",
            "http://localhost:3000/settings?tab=ai#keys",
            "http://127.0.0.1:3000/login",
            "about:blank",
            "blob:http://localhost:3000/5f0c",
        ] {
            assert_eq!(crawler_nav(&url(u)), Nav::Stay, "{u}");
        }
    }

    #[test]
    fn crawler_window_sends_other_sites_to_the_browser() {
        for u in [
            "https://t.me/BotFather",
            "https://localhost:3000/", // https is not the local stack
            "http://localhost:8000/docs",
            "http://localhost.evil.example:3000/",
            "http://example.com:3000/",
            "mailto:team@example.com",
        ] {
            assert_eq!(crawler_nav(&url(u)), Nav::OpenInBrowser, "{u}");
        }
    }

    #[test]
    fn crawler_window_drops_local_and_script_schemes() {
        for u in [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "tauri://localhost/index.html",
        ] {
            assert_eq!(crawler_nav(&url(u)), Nav::Block, "{u}");
        }
    }

    #[test]
    fn setup_window_stays_on_the_bundled_ui() {
        for u in [
            "tauri://localhost/index.html",
            "http://tauri.localhost/index.html",
            "https://tauri.localhost/",
        ] {
            assert_eq!(setup_nav(&url(u), None), Nav::Stay, "{u}");
        }
        assert_eq!(
            setup_nav(
                &url("https://www.docker.com/products/docker-desktop/"),
                None
            ),
            Nav::OpenInBrowser
        );
        assert_eq!(
            setup_nav(&url("http://localhost:3000/"), None),
            Nav::OpenInBrowser
        );
        assert_eq!(setup_nav(&url("file:///tmp/x.html"), None), Nav::Block);
        assert_eq!(setup_nav(&url("tauri://evil/"), None), Nav::Block);
    }

    #[test]
    fn setup_window_accepts_the_dev_server_only_when_given() {
        let dev = url("http://localhost:5174");
        let page = url("http://localhost:5174/index.html");
        assert_eq!(setup_nav(&page, Some(&dev)), Nav::Stay);
        assert_eq!(setup_nav(&page, None), Nav::OpenInBrowser);
        assert_eq!(
            setup_nav(&url("http://localhost:5175/"), Some(&dev)),
            Nav::OpenInBrowser
        );
    }
}

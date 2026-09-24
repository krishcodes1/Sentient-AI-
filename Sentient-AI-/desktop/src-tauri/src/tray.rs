//! The tray / menu-bar icon and its menu:
//! Open Crawler AI · Start · Stop · Show logs · Check for updates · Quit.
//!
//! Why it exists: closing a window only hides it, so the tray is how people get back to the
//! app, control the stack without opening a terminal, and quit. Quit exits the app only — the
//! stack keeps running, so Crawler AI's scheduled work and Telegram replies carry on.

use crawler_ai_desktop::{commands, updates, windows};
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Runtime};

/// Event sent to the setup/status window when the tray asks for the logs view.
pub const SHOW_LOGS_EVENT: &str = "tray://show-logs";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayAction {
    Open,
    Start,
    Stop,
    ShowLogs,
    CheckForUpdates,
    Quit,
}

impl TrayAction {
    pub const ALL: [TrayAction; 6] = [
        TrayAction::Open,
        TrayAction::Start,
        TrayAction::Stop,
        TrayAction::ShowLogs,
        TrayAction::CheckForUpdates,
        TrayAction::Quit,
    ];

    /// Menu item id.
    pub fn id(self) -> &'static str {
        match self {
            TrayAction::Open => "open",
            TrayAction::Start => "start",
            TrayAction::Stop => "stop",
            TrayAction::ShowLogs => "show-logs",
            TrayAction::CheckForUpdates => "check-for-updates",
            TrayAction::Quit => "quit",
        }
    }

    /// Menu item text.
    pub fn label(self) -> &'static str {
        match self {
            TrayAction::Open => "Open Crawler AI",
            TrayAction::Start => "Start",
            TrayAction::Stop => "Stop",
            TrayAction::ShowLogs => "Show logs",
            TrayAction::CheckForUpdates => "Check for updates",
            TrayAction::Quit => "Quit",
        }
    }

    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.id() == id)
    }
}

/// Builds the tray icon. Tauri keeps it alive for the life of the app.
pub fn create<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<()> {
    let item = |action: TrayAction| {
        MenuItem::with_id(app, action.id(), action.label(), true, None::<&str>)
    };
    let menu = Menu::with_items(
        app,
        &[
            &item(TrayAction::Open)?,
            &PredefinedMenuItem::separator(app)?,
            &item(TrayAction::Start)?,
            &item(TrayAction::Stop)?,
            &item(TrayAction::ShowLogs)?,
            &PredefinedMenuItem::separator(app)?,
            &item(TrayAction::CheckForUpdates)?,
            &PredefinedMenuItem::separator(app)?,
            &item(TrayAction::Quit)?,
        ],
    )?;

    let builder = TrayIconBuilder::with_id("crawler-ai")
        .tooltip("Crawler AI")
        .menu(&menu)
        .show_menu_on_left_click(cfg!(target_os = "macos"))
        .on_menu_event(|app, event| {
            if let Some(action) = TrayAction::from_id(event.id().as_ref()) {
                handle(app, action);
            }
        })
        .on_tray_icon_event(|tray, event| {
            if click_opens_app(&event) {
                windows::show_main_window(tray.app_handle());
            }
        });

    // macOS menu bar: a monochrome template image that follows light/dark mode.
    // Windows: the app icon.
    #[cfg(target_os = "macos")]
    let builder = builder
        .icon(tauri::image::Image::from_bytes(include_bytes!(
            "../icons/tray-template.png"
        ))?)
        .icon_as_template(true);
    #[cfg(not(target_os = "macos"))]
    let builder = match app.default_window_icon() {
        Some(icon) => builder.icon(icon.clone()),
        None => builder,
    };

    builder.build(app)?;
    Ok(())
}

/// Windows convention: a left click on the tray icon opens the app and a right click shows the
/// menu. On macOS any click shows the menu, as it does for every menu-bar item.
fn click_opens_app(event: &TrayIconEvent) -> bool {
    !cfg!(target_os = "macos")
        && matches!(
            event,
            TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            }
        )
}

fn handle<R: Runtime>(app: &AppHandle<R>, action: TrayAction) {
    match action {
        TrayAction::Open => windows::show_main_window(app),
        // Start/Stop run in the background and report on the status window's live log.
        TrayAction::Start => {
            commands::start_stack_in_background(app);
            show_status(app);
        }
        TrayAction::Stop => {
            commands::stop_stack_in_background(app);
            show_status(app);
        }
        TrayAction::ShowLogs => {
            show_status(app);
            let _ = app.emit_to(windows::SETUP_WINDOW, SHOW_LOGS_EVENT, ());
        }
        TrayAction::CheckForUpdates => updates::check_in_background(app),
        // Leaves the stack running: Quit closes the app, not Crawler AI.
        TrayAction::Quit => app.exit(0),
    }
}

fn show_status<R: Runtime>(app: &AppHandle<R>) {
    if let Err(err) = windows::show_setup_window(app) {
        eprintln!("crawler-ai: could not open the status window: {err}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn menu_has_the_six_actions_in_order() {
        let labels: Vec<_> = TrayAction::ALL.iter().map(|a| a.label()).collect();
        assert_eq!(
            labels,
            [
                "Open Crawler AI",
                "Start",
                "Stop",
                "Show logs",
                "Check for updates",
                "Quit"
            ]
        );
    }

    #[test]
    fn ids_round_trip_and_are_unique() {
        for action in TrayAction::ALL {
            assert_eq!(TrayAction::from_id(action.id()), Some(action));
        }
        let mut ids: Vec<_> = TrayAction::ALL.iter().map(|a| a.id()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), TrayAction::ALL.len());
        assert_eq!(TrayAction::from_id("nope"), None);
    }
}

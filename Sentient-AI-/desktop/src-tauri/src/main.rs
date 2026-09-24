//! The Crawler AI desktop app: one instance, the tray, and the app's window rules.
//!
//! Launching opens Crawler AI when it is installed and answering, otherwise the setup/status
//! window (see windows.rs for the two windows and their trust levels). Closing a window hides
//! it (the tray icon stays); Quit exits the app and leaves the stack running. A second launch
//! focuses the running app instead of starting another one.
//!
//! Why it exists: the library holds everything testable; this binary adds the parts that only
//! make sense in a running app — plugins, the tray, the update check and the event loop.

// Release builds on Windows must not open a console window next to the app.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(test)]
mod acl_tests;
mod tray;

use crawler_ai_desktop::{commands, windows};
use tauri::WindowEvent;

fn main() {
    let builder = tauri::Builder::default()
        // Registered first: a second launch hands over to this process and exits before
        // anything else in it starts.
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            windows::show_main_window(app)
        }))
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init());

    commands::register(builder)
        .setup(|app| {
            tray::create(app.handle())?;
            windows::show_main_window(app.handle());
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing hides to the tray; only Quit ends the app.
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .build(tauri::generate_context!())
        .expect("Crawler AI failed to start")
        .run(|_app, _event| {
            // Clicking the Dock icon while every window is hidden brings the app back.
            #[cfg(target_os = "macos")]
            if let tauri::RunEvent::Reopen {
                has_visible_windows: false,
                ..
            } = _event
            {
                windows::show_main_window(_app);
            }
        });
}

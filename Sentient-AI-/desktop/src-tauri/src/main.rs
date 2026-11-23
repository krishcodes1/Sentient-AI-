//! The Crawler AI desktop app: one instance, the tray, and the app's window rules.
//!
//! Launching opens Crawler AI when it is installed and answering, otherwise the setup/status
//! window (see windows.rs for the two windows and their trust levels). Closing a window hides
//! it (the tray icon stays); Quit exits the app and leaves the Docker stack running, or stops
//! the native one (a Mac release build, where Crawler AI runs as the app's own processes). A second launch
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
            let handle = app.handle();
            tray::create(handle)?;
            if commands::is_native(handle)
                && commands::is_installed(handle)
                && !windows::crawler_is_up()
            {
                // Mac: opening the app starts Crawler AI; it opens once it answers.
                if let Err(err) = windows::show_setup_window(handle) {
                    eprintln!("crawler-ai: could not open a window: {err}");
                }
                commands::start_then_open(handle);
            } else {
                windows::show_main_window(handle);
            }
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
        .run(|app, event| match event {
            // Clicking the Dock icon while every window is hidden brings the app back.
            #[cfg(target_os = "macos")]
            tauri::RunEvent::Reopen {
                has_visible_windows: false,
                ..
            } => windows::show_main_window(app),
            // The native (Mac) stack is the app's own processes: Quit stops it.
            tauri::RunEvent::Exit => commands::stop_native_on_exit(app),
            _ => {}
        });
}

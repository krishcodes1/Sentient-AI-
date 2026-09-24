//! The Crawler AI desktop app's library: preflight checks, key handling and the Docker
//! Compose stack lifecycle, the Tauri commands that expose them to the setup window, the two
//! app windows and the update check.
//!
//! Why it exists: keeping the logic in a library (and Tauri in `commands`, `windows` and
//! `updates` only) lets `cargo test` cover everything the app does to a user's machine through
//! fakes, with no UI build, no Docker and no real ports involved. The binary (main.rs) only
//! adds the tray and the event loop.

pub mod commands;
pub mod keys;
pub mod platform;
pub mod preflight;
pub mod stack;
pub mod updates;
pub mod windows;

#[cfg(test)]
mod test_support;

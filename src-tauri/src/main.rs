// Tauri v2: thin main.rs wrapper — all logic lives in lib.rs
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    eventbox_desktop_lib::run();
}

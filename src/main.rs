// The windowed program. No console window when started from the Start menu or Explorer.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

fn main() {
    bimbo_guard::run(false);
}

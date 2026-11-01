// No console window when started from the Start menu or Explorer.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod autostart;
mod av;
mod devmon;
mod usb;
mod config;
mod core;
mod engine;
mod feeds;
mod gui;
mod quarantine;
mod scan;
mod startup;
mod system;
mod watcher;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;

const HELP: &str = "Bimbo Guard, a companion malware scanner for Windows

Usage:
  bimbo-guard                      open the app
  bimbo-guard --minimized          open the app minimised (used at sign-in)
  bimbo-guard scan <path>...       scan files or folders
  bimbo-guard quick                quick scan of common malware locations
  bimbo-guard startup              audit programs that run at startup
  bimbo-guard usb                      list USB ports, their type and what is plugged in
  bimbo-guard camera-mic               show which programs use the camera/microphone
  bimbo-guard monitor                  live USB and camera/microphone events (Ctrl+C to stop)
  bimbo-guard status               show Defender and engine status
  bimbo-guard quarantine list
  bimbo-guard quarantine restore <id>
  bimbo-guard quarantine delete <id>
  bimbo-guard import-hashes <file> add SHA-256 hashes from a txt/csv/zip
  bimbo-guard eicar <file>         write the harmless EICAR test file

Options for scan and quick:
  --no-quarantine                      report only, never move files

Exit code is 1 when anything is detected.";

fn attach_console() {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::Console::{ATTACH_PARENT_PROCESS, AttachConsole};
        AttachConsole(ATTACH_PARENT_PROCESS);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let first = args.first().map(String::as_str).unwrap_or("");

    if first.is_empty() || first == "--minimized" {
        run_gui(first == "--minimized");
        return;
    }

    attach_console();
    println!();
    let code = match run_cli(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {e}");
            2
        }
    };
    std::process::exit(code);
}

fn run_gui(minimized: bool) {
    let core = match core::Core::new() {
        Ok(c) => c,
        Err(e) => {
            system::alert("Bimbo Guard", &format!("Could not start: {e}"));
            std::thread::sleep(std::time::Duration::from_secs(30));
            return;
        }
    };
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title(config::APP_NAME)
            .with_inner_size([1120.0, 720.0])
            .with_min_inner_size([560.0, 400.0])
            .with_icon(Arc::new(app_icon())),
        ..Default::default()
    };
    let _ = eframe::run_native(
        config::APP_NAME,
        options,
        Box::new(move |cc| Ok(Box::new(gui::GuiApp::new(cc, core, minimized)))),
    );
}

/// A small shield drawn in code, so no image file is needed.
fn app_icon() -> eframe::egui::IconData {
    let n = 64usize;
    let mut rgba = vec![0u8; n * n * 4];
    for y in 0..n {
        for x in 0..n {
            let fx = (x as f32 + 0.5) / n as f32 * 2.0 - 1.0;
            let fy = (y as f32 + 0.5) / n as f32;
            // Shield: straight top, sides curving to a point at the bottom.
            let half = if fy < 0.45 { 0.82 } else { 0.82 * (1.0 - (fy - 0.45) / 0.53).max(0.0).sqrt() };
            let inside = fy > 0.06 && fy < 0.98 && fx.abs() < half;
            let inner = fy > 0.16 && fy < 0.88 && fx.abs() < half - 0.16;
            let i = (y * n + x) * 4;
            if inside {
                let (r, g, b) = if inner { (232, 163, 61) } else { (60, 40, 20) };
                rgba[i..i + 4].copy_from_slice(&[r, g, b, 255]);
            }
        }
    }
    eframe::egui::IconData { rgba, width: n as u32, height: n as u32 }
}

fn print_detection(d: &engine::Detection, action: &str) {
    println!("[{}] {}", d.severity().label(), d.path.display());
    for f in &d.findings {
        println!("    {} ({}): {}", f.name, f.source, f.description);
    }
    if let Some(df) = &d.defender {
        println!("    {df}");
    }
    println!("    sha256 {}", d.sha256);
    println!("    action: {action}");
}

fn run_cli(args: &[String]) -> anyhow::Result<i32> {
    let cmd = args[0].as_str();
    let rest = &args[1..];
    let no_q = rest.iter().any(|a| a == "--no-quarantine");
    let paths: Vec<PathBuf> = rest.iter().filter(|a| !a.starts_with("--")).map(PathBuf::from).collect();

    match cmd {
        "-h" | "--help" | "help" => {
            println!("{HELP}");
            Ok(0)
        }
        "eicar" => {
            let p = paths.first().ok_or_else(|| anyhow::anyhow!("give a file name"))?;
            // Stored reversed so the program file itself does not contain the test string.
            let eicar: String = "*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X".chars().rev().collect();
            std::fs::write(p, eicar)?;
            println!("Wrote the harmless EICAR test file to {}", p.display());
            println!("Note: Microsoft Defender may remove it within seconds; that is expected.");
            Ok(0)
        }
        "scan" | "quick" => {
            let core = core::Core::new()?;
            let roots = if cmd == "quick" { scan::quick_scan_roots() } else { paths };
            if roots.is_empty() {
                anyhow::bail!("give at least one file or folder to scan");
            }
            let e = core.engine();
            println!("Bimbo Guard: {} rules, {} known-bad hashes", e.rule_count, e.hash_count());
            for r in &roots {
                println!("Scanning {}", r.display());
            }
            let progress = Arc::new(scan::ScanProgress::default());
            *progress.label.lock().unwrap() = if cmd == "quick" { "Quick scan".into() } else { "Command-line scan".into() };
            scan::run_scan(core.clone(), roots, progress.clone(), !no_q);
            let results = progress.results.lock().unwrap().clone();
            println!();
            for (d, a) in &results {
                print_detection(d, a);
            }
            println!(
                "\n{} files checked, {} skipped, {} detection(s), {:.1} s",
                progress.scanned.load(Ordering::Relaxed),
                progress.skipped.load(Ordering::Relaxed),
                results.len(),
                progress.elapsed_secs()
            );
            Ok(if results.is_empty() { 0 } else { 1 })
        }
        "startup" => {
            let core = core::Core::new()?;
            let entries = startup::audit(&core.engine(), rest.iter().any(|a| a == "--all"));
            let mut bad = 0;
            for e in &entries {
                let mark = if e.is_concerning() { "!!" } else { "ok" };
                println!("[{mark}] {} | {} | {}", e.location, e.name, e.command);
                for f in &e.flags {
                    println!("       {f}");
                }
                if let Some(d) = &e.detection {
                    println!("       {}: {}", d.severity().label(), d.summary());
                }
                if e.is_concerning() {
                    bad += 1;
                }
            }
            println!("\n{} entries, {} worth a look", entries.len(), bad);
            Ok(if bad > 0 { 1 } else { 0 })
        }
        "usb" => {
            let r = usb::scan();
            for e in &r.errors {
                println!("Note: {e}");
            }
            let s = r.summary();
            println!("Built-in USB ports: {} total, {} in use, {} free", s.built_in, s.built_in_in_use, s.built_in_free);
            println!("  USB 3.x: {}   USB 2.0 only: {}   USB-C: {}", s.built_in_usb3, s.built_in_usb2_only, s.built_in_type_c);
            if s.hub_ports > 0 {
                println!("Ports on hubs/docks: {} ({} in use)", s.hub_ports, s.hub_ports_in_use);
            }
            println!("Internal devices (webcam, Bluetooth...): {}", s.internal_devices);
            println!();
            for p in &r.ports {
                let state = match &p.device {
                    Some(d) => format!("IN USE  {} (ID {:04X}:{:04X}), {}", d.name, d.vid, d.pid, d.speed_text()),
                    None => "free".into(),
                };
                println!("{:<12} {:<8} {:<16} {:?}  {}", p.label, p.kind(), p.connector(), p.location, state);
                if let Some(w) = p.slow_link_warning() {
                    println!("             ! {w}");
                }
                if rest.iter().any(|a| a == "--detail") {
                    println!("             logical: {}", p.logical.join(", "));
                }
            }
            println!("\n{} hub(s) read.", r.hubs_seen);
            Ok(0)
        }
        "camera-mic" | "privacy" => {
            let core = core::Core::new()?;
            let r = av::scan(Some(&core.engine()));
            for e in &r.errors {
                println!("Note: {e}");
            }
            for (k, v) in &r.access_setting {
                println!("{k} access for apps: {v}");
            }
            let active: Vec<_> = r.active().collect();
            println!();
            if active.is_empty() {
                println!("Camera and microphone are NOT in use right now.");
            }
            for e in &active {
                println!("IN USE  {:<10} {}", e.device.label(), e.app_name);
                if let Some(p) = &e.exe {
                    println!("        {}", p.display());
                }
                for f in &e.flags {
                    println!("        ! {f}");
                }
            }
            println!("\nHistory (Windows' own record):");
            for e in r.entries.iter().filter(|e| !e.in_use) {
                println!(
                    "  {:<10} {:<40} last used {}",
                    e.device.label(),
                    e.app_name,
                    e.last_start.map(|t| t.format("%Y-%m-%d %H:%M").to_string()).unwrap_or_default()
                );
            }
            Ok(if active.is_empty() { 0 } else { 1 })
        }
        "monitor" => {
            let core = core::Core::new()?;
            let m = devmon::DeviceMonitor::start(core.clone(), false);
            {
                let s = m.usb.lock().unwrap().summary();
                println!("Watching. Built-in USB ports: {} ({} in use, {} free). Press Ctrl+C to stop.", s.built_in, s.built_in_in_use, s.built_in_free);
                for e in m.av.lock().unwrap().active() {
                    println!("{} already ON: {}", e.device.label(), e.app_name);
                }
            }
            let mut shown = 0;
            loop {
                std::thread::sleep(std::time::Duration::from_millis(500));
                let f = m.feed.lock().unwrap();
                for e in f.iter().skip(shown) {
                    println!("{}  {}{}", e.time.format("%H:%M:%S"), if e.warning { "WARNING " } else { "" }, e.message);
                }
                shown = f.len();
            }
        }
        "status" => {
            let core = core::Core::new()?;
            let e = core.engine();
            println!("Data folder : {}", core.paths.root.display());
            println!("Rules       : {}", e.rule_count);
            println!("Hashes      : {}", e.hash_count());
            for err in &e.rule_errors {
                println!("Rule error  : {err}");
            }
            let d = system::defender_status();
            if d.available {
                println!("Defender    : antivirus {}, real-time {}, signatures {} ({})",
                    if d.antivirus_enabled { "on" } else { "OFF" },
                    if d.realtime_enabled { "on" } else { "OFF" },
                    d.signatures_updated, d.signature_version);
            } else {
                println!("Defender    : {}", d.error.unwrap_or_default());
            }
            println!("MpCmdRun    : {}", system::find_mpcmdrun().map(|p| p.display().to_string()).unwrap_or("not found".into()));
            Ok(0)
        }
        "quarantine" => {
            let core = core::Core::new()?;
            match rest.first().map(String::as_str) {
                Some("list") | None => {
                    let items = quarantine::list(&core.paths);
                    if items.is_empty() {
                        println!("Quarantine is empty.");
                    }
                    for it in items {
                        println!("{}  {}  {}", it.id, it.original_path.display(), it.reason);
                    }
                    Ok(0)
                }
                Some("restore") => {
                    let id = rest.get(1).ok_or_else(|| anyhow::anyhow!("give an id"))?;
                    let p = quarantine::restore(&core.paths, id, None)?;
                    println!("Restored to {}", p.display());
                    Ok(0)
                }
                Some("delete") => {
                    let id = rest.get(1).ok_or_else(|| anyhow::anyhow!("give an id"))?;
                    quarantine::delete(&core.paths, id)?;
                    println!("Deleted.");
                    Ok(0)
                }
                Some(other) => anyhow::bail!("unknown quarantine command '{other}'"),
            }
        }
        "import-hashes" => {
            let core = core::Core::new()?;
            let f = paths.first().ok_or_else(|| anyhow::anyhow!("give a file"))?;
            let n = feeds::import_file(&core, f)?;
            println!("Added {n} new hashes.");
            Ok(0)
        }
        other => {
            println!("Unknown command '{other}'.\n\n{HELP}");
            Ok(2)
        }
    }
}

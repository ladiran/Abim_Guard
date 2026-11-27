//! Real-time protection from user mode: watches chosen folders and new USB
//! drives, and scans files shortly after they are written.

use crate::core::Core;
use crate::engine::{Detection, ScanOutcome};
use crate::scan::ScanProgress;
use notify::{EventKind, RecursiveMode, Watcher};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Browser download placeholders: wait for the real file instead.
const PARTIAL_EXTS: &[&str] = &["crdownload", "part", "partial", "download", "tmp", "opdownload"];

pub struct Realtime {
    stop: Arc<AtomicBool>,
    pub files_checked: Arc<AtomicU64>,
    pub watching: Arc<Mutex<Vec<PathBuf>>>,
    pub alerts: Arc<Mutex<Vec<(Detection, String)>>>,
    /// Quick scans of USB drives started when they were plugged in.
    pub usb_scans: Arc<Mutex<Vec<Arc<ScanProgress>>>>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Realtime {
    pub fn start(core: Arc<Core>, popup_alerts: bool) -> anyhow::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let files_checked = Arc::new(AtomicU64::new(0));
        let watching = Arc::new(Mutex::new(Vec::new()));
        let alerts = Arc::new(Mutex::new(Vec::new()));
        let usb_scans: Arc<Mutex<Vec<Arc<ScanProgress>>>> = Arc::new(Mutex::new(Vec::new()));

        let (tx, rx) = crossbeam_channel::unbounded::<notify::Result<notify::Event>>();
        let mut watcher = notify::recommended_watcher(move |res| {
            let _ = tx.send(res);
        })?;

        let settings = core.settings();
        let mut watched = Vec::new();
        for f in &settings.watched_folders {
            match watcher.watch(f, RecursiveMode::Recursive) {
                Ok(()) => watched.push(f.clone()),
                Err(e) => core.log("watch", format!("Cannot watch {}: {e}", f.display()), Some(f), None),
            }
        }
        *watching.lock().unwrap() = watched.clone();
        core.log("watch", format!("Real-time protection started on {} folder(s)", watched.len()), None, None);

        let (s, fc, w, a) = (stop.clone(), files_checked.clone(), watching.clone(), alerts.clone());
        let us = usb_scans.clone();
        let handle = std::thread::spawn(move || {
            let mut watcher = watcher;
            let mut pending: HashMap<PathBuf, Instant> = HashMap::new();
            let mut recently: HashMap<PathBuf, Instant> = HashMap::new();
            let mut known_drives: HashSet<PathBuf> = crate::system::removable_drives().into_iter().collect();
            let mut last_drive_check = Instant::now();
            let mut engine = core.engine();

            while !s.load(Ordering::Relaxed) {
                // Collect file events.
                while let Ok(res) = rx.try_recv() {
                    if let Ok(ev) = res {
                        if matches!(ev.kind, EventKind::Create(_) | EventKind::Modify(_)) {
                            for p in ev.paths {
                                pending.insert(p, Instant::now());
                            }
                        }
                    }
                }

                // Pick up rule reloads.
                let latest = core.engine();
                if !Arc::ptr_eq(&latest, &engine) {
                    engine = latest;
                }

                // Scan files that have been quiet for 2 seconds.
                let now = Instant::now();
                let ready: Vec<PathBuf> = pending
                    .iter()
                    .filter(|(_, t)| now.duration_since(**t) > Duration::from_secs(2))
                    .map(|(p, _)| p.clone())
                    .collect();
                if !ready.is_empty() {
                    let mut scanner = engine.scanner();
                    for p in ready {
                        pending.remove(&p);
                        if should_skip(&p, &core) {
                            continue;
                        }
                        if let Some(t) = recently.get(&p) {
                            if now.duration_since(*t) < Duration::from_secs(10) {
                                continue;
                            }
                        }
                        recently.insert(p.clone(), now);
                        fc.fetch_add(1, Ordering::Relaxed);
                        if let ScanOutcome::Detected(d) = engine.scan_file(&mut scanner, &p) {
                            let (d, action) = core.handle_detection(d, true);
                            if popup_alerts {
                                crate::system::notify(
                                    &format!("Threat found: {}", d.severity().label()),
                                    &format!(
                                        "{}\n{}\nAction: {}",
                                        d.path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(),
                                        d.summary(),
                                        action
                                    ),
                                    true,
                                );
                            }
                            a.lock().unwrap().push((d, action));
                        }
                    }
                    recently.retain(|_, t| now.duration_since(*t) < Duration::from_secs(60));
                }

                // New USB drive? Watch it and scan what is already on it.
                if settings.watch_removable_drives && last_drive_check.elapsed() > Duration::from_secs(5) {
                    last_drive_check = Instant::now();
                    let current: HashSet<PathBuf> = crate::system::removable_drives().into_iter().collect();
                    for d in current.difference(&known_drives) {
                        // Watch it for new files...
                        if watcher.watch(d, RecursiveMode::Recursive).is_ok() {
                            w.lock().unwrap().push(d.clone());
                        }
                        // ...and quick-scan everything already on it.
                        if core.settings().usb_auto_scan {
                            core.log("watch", format!("USB drive {} connected; quick-scanning the whole drive", d.display()), Some(d), None);
                            let p = start_usb_scan(core.clone(), d.clone(), a.clone(), popup_alerts);
                            let mut list = us.lock().unwrap();
                            list.retain(|x| !x.done.load(Ordering::Relaxed));
                            list.push(p);
                        } else {
                            core.log("watch", format!("USB drive {} connected; watching it for new files", d.display()), Some(d), None);
                        }
                    }
                    for d in known_drives.difference(&current) {
                        let _ = watcher.unwatch(d);
                        w.lock().unwrap().retain(|x| x != d);
                    }
                    known_drives = current;
                }

                std::thread::sleep(Duration::from_millis(400));
            }
            core.log("watch", "Real-time protection stopped".into(), None, None);
        });

        Ok(Self { stop, files_checked, watching, alerts, usb_scans, handle: Some(handle) })
    }

    pub fn stop(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for p in self.usb_scans.lock().unwrap().iter() {
            p.cancel.store(true, Ordering::SeqCst);
        }
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Quick-scan a newly connected USB drive on its own thread: every folder,
/// no size limit, checking the file types malware uses. Detections are
/// handled like any other (quarantine per settings) and shown on Overview.
fn start_usb_scan(
    core: Arc<Core>,
    drive: PathBuf,
    alerts: Arc<Mutex<Vec<(Detection, String)>>>,
    popups: bool,
) -> Arc<ScanProgress> {
    let p = Arc::new(ScanProgress::default());
    p.quick_types_only.store(true, Ordering::SeqCst);
    let name = drive.display().to_string();
    *p.label.lock().unwrap() = format!("USB drive {name} quick scan");
    if popups {
        crate::system::notify("Checking USB drive", &format!("Abim Guard is quick-scanning {name}."), false);
    }
    let p2 = p.clone();
    std::thread::spawn(move || {
        crate::scan::run_scan(core, vec![drive], p2.clone(), true);
        let results = p2.results.lock().unwrap().clone();
        let checked = p2.scanned.load(Ordering::Relaxed);
        if popups {
            if results.is_empty() {
                if !p2.cancel.load(Ordering::Relaxed) {
                    crate::system::notify(
                        "USB drive checked",
                        &format!("{name}: {checked} file(s) checked, no threats found."),
                        false,
                    );
                }
            } else {
                crate::system::notify(
                    "Threat found on USB drive",
                    &format!("{name}: {} detection(s). Open Abim Guard to see them.", results.len()),
                    true,
                );
            }
        }
        alerts.lock().unwrap().extend(results);
    });
    p
}

fn should_skip(p: &Path, core: &Core) -> bool {
    if !p.is_file() || p.starts_with(&core.paths.root) {
        return true;
    }
    let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
    if PARTIAL_EXTS.contains(&ext.as_str()) {
        return true;
    }
    core.settings().exclusions.iter().any(|e| p.starts_with(e))
}

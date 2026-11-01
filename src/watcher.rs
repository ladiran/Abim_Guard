//! Real-time protection from user mode: watches chosen folders and new USB
//! drives, and scans files shortly after they are written.

use crate::core::Core;
use crate::engine::{Detection, ScanOutcome};
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
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Realtime {
    pub fn start(core: Arc<Core>, popup_alerts: bool) -> anyhow::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let files_checked = Arc::new(AtomicU64::new(0));
        let watching = Arc::new(Mutex::new(Vec::new()));
        let alerts = Arc::new(Mutex::new(Vec::new()));

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
                                crate::system::alert(
                                    "Bimbo Guard: threat found",
                                    &format!(
                                        "{}\n\n{} ({})\n\nAction: {}",
                                        d.path.display(),
                                        d.summary(),
                                        d.severity().label(),
                                        action
                                    ),
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
                        core.log("watch", format!("Removable drive {} connected; scanning it", d.display()), Some(d), None);
                        if watcher.watch(d, RecursiveMode::Recursive).is_ok() {
                            w.lock().unwrap().push(d.clone());
                        }
                        for e in walkdir::WalkDir::new(d).max_depth(6).into_iter().flatten() {
                            if e.file_type().is_file() {
                                pending.insert(e.into_path(), Instant::now() - Duration::from_secs(3));
                            }
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

        Ok(Self { stop, files_checked, watching, alerts, handle: Some(handle) })
    }

    pub fn stop(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
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

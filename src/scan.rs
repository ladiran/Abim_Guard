//! Multi-threaded folder scans with progress and cancel.

use crate::core::Core;
use crate::engine::{Detection, ScanOutcome};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Default)]
pub struct ScanProgress {
    pub scanned: AtomicU64,
    pub skipped: AtomicU64,
    pub bytes: AtomicU64,
    pub cancel: AtomicBool,
    pub done: AtomicBool,
    pub current: Mutex<String>,
    pub results: Mutex<Vec<(Detection, String)>>,
    pub started: Mutex<Option<Instant>>,
    pub finished: Mutex<Option<Instant>>,
    pub label: Mutex<String>,
}

impl ScanProgress {
    pub fn elapsed_secs(&self) -> f64 {
        let s = *self.started.lock().unwrap();
        let f = *self.finished.lock().unwrap();
        match (s, f) {
            (Some(s), Some(f)) => (f - s).as_secs_f64(),
            (Some(s), None) => s.elapsed().as_secs_f64(),
            _ => 0.0,
        }
    }
}

/// Folders a full scan skips: huge, protected, and not useful to pattern scan.
fn skip_dir(p: &Path, core: &Core, exclusions: &[PathBuf]) -> bool {
    let s = p.to_string_lossy().to_ascii_lowercase().replace('/', "\\");
    const SKIP: &[&str] = &[
        "\\windows\\winsxs",
        "\\windows\\installer",
        "\\windows\\softwaredistribution",
        "\\system volume information",
        "\\windows defender\\definition updates",
        "\\microsoft\\windows defender\\scans",
    ];
    if SKIP.iter().any(|k| s.ends_with(k)) {
        return true;
    }
    if p.starts_with(&core.paths.quarantine) {
        return true;
    }
    exclusions.iter().any(|e| p.starts_with(e))
}

/// Quick scan locations: where malware usually lands or hides.
pub fn quick_scan_roots() -> Vec<PathBuf> {
    let mut v = Vec::new();
    for d in [dirs::download_dir(), dirs::desktop_dir(), dirs::document_dir()].into_iter().flatten() {
        v.push(d);
    }
    v.push(std::env::temp_dir());
    if let Some(d) = dirs::config_dir() {
        v.push(d.join(r"Microsoft\Windows\Start Menu\Programs\Startup"));
    }
    if cfg!(windows) {
        v.push(PathBuf::from(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"));
        v.push(PathBuf::from(r"C:\Users\Public"));
    }
    v.retain(|p| p.exists());
    v.dedup();
    v
}

/// Run a scan on the calling thread (call it from a background thread).
pub fn run_scan(core: Arc<Core>, roots: Vec<PathBuf>, progress: Arc<ScanProgress>, auto_quarantine: bool) {
    *progress.started.lock().unwrap() = Some(Instant::now());
    let engine = core.engine();
    let exclusions = core.settings().exclusions;
    let workers = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2).clamp(1, 8);
    let (tx, rx) = crossbeam_channel::bounded::<PathBuf>(4096);

    std::thread::scope(|scope| {
        // Producer: walk folders.
        let walker_progress = progress.clone();
        let core_w = core.clone();
        scope.spawn(move || {
            for root in &roots {
                if walker_progress.cancel.load(Ordering::Relaxed) {
                    break;
                }
                let it = walkdir::WalkDir::new(root)
                    .follow_links(false)
                    .into_iter()
                    .filter_entry(|e| !(e.file_type().is_dir() && skip_dir(e.path(), &core_w, &exclusions)));
                for entry in it {
                    if walker_progress.cancel.load(Ordering::Relaxed) {
                        break;
                    }
                    match entry {
                        Ok(e) if e.file_type().is_file() => {
                            if tx.send(e.into_path()).is_err() {
                                return;
                            }
                        }
                        Ok(_) => {}
                        Err(_) => {
                            walker_progress.skipped.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
            drop(tx);
        });

        // Consumers: scan files.
        for _ in 0..workers {
            let rx = rx.clone();
            let engine = engine.clone();
            let progress = progress.clone();
            let core = core.clone();
            scope.spawn(move || {
                let mut scanner = engine.scanner();
                for path in rx.iter() {
                    if progress.cancel.load(Ordering::Relaxed) {
                        break;
                    }
                    if let Ok(mut c) = progress.current.try_lock() {
                        *c = path.display().to_string();
                    }
                    match engine.scan_file(&mut scanner, &path) {
                        ScanOutcome::Clean => {}
                        ScanOutcome::Skipped(_) => {
                            progress.skipped.fetch_add(1, Ordering::Relaxed);
                        }
                        ScanOutcome::Detected(d) => {
                            let r = core.handle_detection(d, auto_quarantine);
                            progress.results.lock().unwrap().push(r);
                        }
                    }
                    if let Ok(m) = std::fs::metadata(&path) {
                        progress.bytes.fetch_add(m.len(), Ordering::Relaxed);
                    }
                    progress.scanned.fetch_add(1, Ordering::Relaxed);
                }
            });
        }
        drop(rx);
    });

    *progress.finished.lock().unwrap() = Some(Instant::now());
    let n = progress.results.lock().unwrap().len();
    let label = progress.label.lock().unwrap().clone();
    core.log(
        "scan",
        format!(
            "{} {}: {} files checked, {} detections, {:.0} s",
            label,
            if progress.cancel.load(Ordering::Relaxed) { "stopped" } else { "finished" },
            progress.scanned.load(Ordering::Relaxed),
            n,
            progress.elapsed_secs()
        ),
        None,
        None,
    );
    progress.done.store(true, Ordering::SeqCst);
}

//! Shared state, detection handling and the event log.

use crate::config::{AppPaths, Settings};
use crate::engine::{Detection, Engine};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub time: chrono::DateTime<chrono::Local>,
    pub kind: String,
    pub message: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
}

pub struct Core {
    pub paths: AppPaths,
    pub settings: RwLock<Settings>,
    pub engine: RwLock<Arc<Engine>>,
    pub recent: Mutex<Vec<Event>>,
    log_lock: Mutex<()>,
}

impl Core {
    pub fn new() -> anyhow::Result<Arc<Self>> {
        let paths = AppPaths::new()?;
        let settings = Settings::load(&paths);
        let engine = Engine::load(&paths, settings.max_scan_mb)?;
        let core = Arc::new(Self {
            recent: Mutex::new(load_recent(&paths, 300)),
            paths,
            settings: RwLock::new(settings),
            engine: RwLock::new(Arc::new(engine)),
            log_lock: Mutex::new(()),
        });
        Ok(core)
    }

    pub fn engine(&self) -> Arc<Engine> {
        self.engine.read().unwrap().clone()
    }

    pub fn settings(&self) -> Settings {
        self.settings.read().unwrap().clone()
    }

    pub fn save_settings(&self, s: Settings) -> anyhow::Result<()> {
        s.save(&self.paths)?;
        *self.settings.write().unwrap() = s;
        Ok(())
    }

    pub fn reload_engine(&self) -> anyhow::Result<Arc<Engine>> {
        let e = Arc::new(Engine::load(&self.paths, self.settings().max_scan_mb)?);
        *self.engine.write().unwrap() = e.clone();
        self.log("engine", format!("Loaded {} rules and {} known-bad hashes", e.rule_count, e.hash_count()), None, None);
        Ok(e)
    }

    pub fn log(&self, kind: &str, message: String, path: Option<&Path>, severity: Option<&str>) {
        let ev = Event {
            time: chrono::Local::now(),
            kind: kind.into(),
            message,
            path: path.map(|p| p.display().to_string()),
            severity: severity.map(String::from),
        };
        {
            let _g = self.log_lock.lock().unwrap();
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(self.paths.logs.join("events.jsonl"))
            {
                if let Ok(line) = serde_json::to_string(&ev) {
                    let _ = writeln!(f, "{line}");
                }
            }
        }
        let mut r = self.recent.lock().unwrap();
        r.push(ev);
        let n = r.len();
        if n > 500 {
            r.drain(0..n - 500);
        }
    }

    /// Second opinion, auto-quarantine and logging for one detection.
    /// Returns the (possibly updated) detection and what was done.
    pub fn handle_detection(&self, mut det: Detection, allow_auto_quarantine: bool) -> (Detection, String) {
        let s = self.settings();
        if s.defender_second_opinion && cfg!(windows) {
            det.defender = Some(match crate::system::defender_scan(&det.path) {
                Ok(None) => "Defender: no threat found".into(),
                Ok(Some(t)) => format!("Defender also detects: {t}"),
                Err(e) => format!("Defender check unavailable ({e})"),
            });
        }
        let sev = det.severity();
        let mut action = "Reported".to_string();
        if allow_auto_quarantine && s.auto_quarantine && sev.quarantine_worthy() {
            match crate::quarantine::quarantine(&self.paths, &det.path, &det.sha256, &det.summary()) {
                Ok(_) => action = "Quarantined".into(),
                Err(e) => action = format!("Quarantine failed: {e}"),
            }
        }
        self.log(
            "detection",
            format!(
                "{} [{}] {}{}",
                det.summary(),
                sev.label(),
                action,
                det.defender.as_ref().map(|d| format!(". {d}")).unwrap_or_default()
            ),
            Some(&det.path),
            Some(sev.label()),
        );
        (det, action)
    }
}

fn load_recent(paths: &AppPaths, n: usize) -> Vec<Event> {
    let text = std::fs::read_to_string(paths.logs.join("events.jsonl")).unwrap_or_default();
    let mut v: Vec<Event> = text.lines().filter_map(|l| serde_json::from_str(l).ok()).collect();
    if v.len() > n {
        v.drain(0..v.len() - n);
    }
    v
}

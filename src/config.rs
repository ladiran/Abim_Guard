//! App data locations and user settings.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const APP_NAME: &str = "Bimbo Guard";

/// All folders the app keeps its data in, under %LOCALAPPDATA%\BimboGuard.
#[derive(Clone, Debug)]
pub struct AppPaths {
    pub root: PathBuf,
    pub rules: PathBuf,
    pub quarantine: PathBuf,
    pub logs: PathBuf,
    pub hashes_file: PathBuf,
    pub settings_file: PathBuf,
}

impl AppPaths {
    pub fn new() -> anyhow::Result<Self> {
        let base = std::env::var_os("BIMBO_GUARD_HOME")
            .map(PathBuf::from)
            .or_else(crate::package::packaged_data_dir)
            .or_else(|| dirs::data_local_dir().map(|d| d.join("BimboGuard")))
            .ok_or_else(|| anyhow::anyhow!("cannot find a local app data folder"))?;
        if crate::package::is_packaged() {
            crate::package::migrate_from_unpackaged(&base);
        }
        Self::at(&base)
    }

    pub fn at(base: &Path) -> anyhow::Result<Self> {
        let p = Self {
            root: base.to_path_buf(),
            rules: base.join("rules"),
            quarantine: base.join("quarantine"),
            logs: base.join("logs"),
            hashes_file: base.join("known_bad_sha256.txt"),
            settings_file: base.join("settings.json"),
        };
        for d in [&p.root, &p.rules, &p.quarantine, &p.logs] {
            std::fs::create_dir_all(d)?;
        }
        Ok(p)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Folders watched in real time.
    pub watched_folders: Vec<PathBuf>,
    /// Also scan USB / removable drives when they are plugged in.
    pub watch_removable_drives: bool,
    /// Start real-time watching when the app opens.
    pub realtime_on_start: bool,
    /// Move "malicious" detections into quarantine automatically.
    pub auto_quarantine: bool,
    /// Ask Microsoft Defender for a second opinion on detections.
    pub defender_second_opinion: bool,
    /// Files bigger than this (MB) are hashed but not pattern scanned.
    pub max_scan_mb: u64,
    /// Optional URL of a SHA-256 hash feed (plain text, CSV or zip).
    pub hash_feed_url: String,
    /// Folders never scanned.
    pub exclusions: Vec<PathBuf>,
    /// Watch USB ports and camera/microphone use in real time.
    pub device_monitor: bool,
    /// Pop-up when a USB device is plugged in or removed.
    pub usb_popups: bool,
    /// Pop-up when the camera or microphone is switched on.
    pub av_popups: bool,
    /// Apps allowed to use the camera/microphone without a pop-up
    /// (still logged). Registry ids, lower case.
    pub trusted_av_apps: Vec<String>,
    /// Closing the window keeps Bimbo Guard running in the system tray.
    pub close_to_tray: bool,
}

impl Default for Settings {
    fn default() -> Self {
        let mut watched = Vec::new();
        if let Some(d) = dirs::download_dir() {
            watched.push(d);
        }
        if let Some(d) = dirs::desktop_dir() {
            watched.push(d);
        }
        Self {
            watched_folders: watched,
            watch_removable_drives: true,
            realtime_on_start: true,
            auto_quarantine: true,
            defender_second_opinion: true,
            max_scan_mb: 100,
            hash_feed_url: String::new(),
            exclusions: Vec::new(),
            device_monitor: true,
            usb_popups: true,
            av_popups: true,
            trusted_av_apps: Vec::new(),
            close_to_tray: true,
        }
    }
}

impl Settings {
    pub fn load(paths: &AppPaths) -> Self {
        std::fs::read_to_string(&paths.settings_file)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, paths: &AppPaths) -> anyhow::Result<()> {
        std::fs::write(&paths.settings_file, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }
}

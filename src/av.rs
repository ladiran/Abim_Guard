//! Camera and microphone watch.
//!
//! Windows records every app that opens the camera or microphone under
//! HKCU (and HKLM) \Software\Microsoft\Windows\CurrentVersion\
//! CapabilityAccessManager\ConsentStore\{webcam,microphone}.
//! Each app has LastUsedTimeStart / LastUsedTimeStop (FILETIME). While an app
//! is using the device, LastUsedTimeStop is 0. Desktop programs sit under the
//! "NonPackaged" subkey, named by their path with '#' instead of '\'.

use serde::Serialize;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, PartialOrd, Ord)]
pub enum Device {
    Camera,
    Microphone,
}

impl Device {
    pub fn label(self) -> &'static str {
        match self {
            Device::Camera => "Camera",
            Device::Microphone => "Microphone",
        }
    }
    #[cfg_attr(not(windows), allow(dead_code))]
    fn store_key(self) -> &'static str {
        match self {
            Device::Camera => "webcam",
            Device::Microphone => "microphone",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct AvUse {
    pub device: Device,
    /// Registry key name: package family name or '#'-path.
    pub app_id: String,
    pub app_name: String,
    pub exe: Option<PathBuf>,
    pub packaged: bool,
    pub in_use: bool,
    pub last_start: Option<chrono::DateTime<chrono::Local>>,
    pub last_stop: Option<chrono::DateTime<chrono::Local>>,
    /// Filled in for apps currently using a device.
    pub flags: Vec<String>,
    pub has_visible_window: Option<bool>,
}

impl AvUse {
    pub fn key(&self) -> (Device, String) {
        (self.device, self.app_id.to_ascii_lowercase())
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct AvReport {
    pub entries: Vec<AvUse>,
    /// Windows privacy switch per device ("Allow" / "Deny"), if readable.
    pub access_setting: HashMap<String, String>,
    pub errors: Vec<String>,
}

impl AvReport {
    pub fn active(&self) -> impl Iterator<Item = &AvUse> {
        self.entries.iter().filter(|e| e.in_use)
    }
}

/// FILETIME (100 ns ticks since 1601) to local time.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
pub fn filetime(ft: u64) -> Option<chrono::DateTime<chrono::Local>> {
    if ft == 0 {
        return None;
    }
    let secs = (ft / 10_000_000) as i64 - 11_644_473_600;
    let nanos = ((ft % 10_000_000) * 100) as u32;
    chrono::DateTime::from_timestamp(secs, nanos).map(|t| t.with_timezone(&chrono::Local))
}

/// "C:#Program Files#Zoom#bin#Zoom.exe" -> path and short name.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
pub fn decode_nonpackaged(id: &str) -> (PathBuf, String) {
    let p = id.replace('#', "\\");
    let name = p.rsplit('\\').next().unwrap_or(&p).to_string();
    (PathBuf::from(p), name)
}

/// "Microsoft.WindowsCamera_8wekyb3d8bbwe" -> "Microsoft.WindowsCamera".
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
pub fn packaged_name(id: &str) -> String {
    id.split('_').next().unwrap_or(id).to_string()
}

#[derive(Clone, Debug, PartialEq)]
pub enum AvChange {
    Started { device: Device, app: String, exe: Option<PathBuf>, flags: Vec<String>, app_id: String },
    Stopped { device: Device, app: String, seconds: Option<i64> },
}

impl AvChange {
    pub fn message(&self) -> String {
        match self {
            AvChange::Started { device, app, exe, flags, .. } => {
                let mut m = format!("{} turned ON by {}", device.label(), app);
                if let Some(e) = exe {
                    m.push_str(&format!(" ({})", e.display()));
                }
                if !flags.is_empty() {
                    m.push_str(&format!(". Warning: {}", flags.join("; ")));
                }
                m
            }
            AvChange::Stopped { device, app, seconds } => match seconds {
                Some(s) => format!("{} turned off by {} after {}", device.label(), app, duration_text(*s)),
                None => format!("{} turned off by {}", device.label(), app),
            },
        }
    }
}

pub fn duration_text(s: i64) -> String {
    if s < 60 {
        format!("{s} s")
    } else if s < 3600 {
        format!("{} min {} s", s / 60, s % 60)
    } else {
        format!("{} h {} min", s / 3600, (s % 3600) / 60)
    }
}

pub fn diff(old: &AvReport, new: &AvReport) -> Vec<AvChange> {
    let was: HashMap<(Device, String), &AvUse> = old.active().map(|e| (e.key(), e)).collect();
    let now: HashMap<(Device, String), &AvUse> = new.active().map(|e| (e.key(), e)).collect();
    let mut out = Vec::new();
    for (k, e) in &now {
        if !was.contains_key(k) {
            out.push(AvChange::Started {
                device: e.device,
                app: e.app_name.clone(),
                exe: e.exe.clone(),
                flags: e.flags.clone(),
                app_id: e.app_id.clone(),
            });
        }
    }
    for (k, e) in &was {
        if !now.contains_key(k) {
            // Look up the stop time the app just recorded.
            let finished = new.entries.iter().find(|n| n.key() == *k);
            let seconds = match (e.last_start, finished.and_then(|f| f.last_stop)) {
                (Some(a), Some(b)) => Some((b - a).num_seconds().max(0)),
                _ => None,
            };
            out.push(AvChange::Stopped { device: e.device, app: e.app_name.clone(), seconds });
        }
    }
    out.sort_by_key(|c| match c {
        AvChange::Started { .. } => 1,
        AvChange::Stopped { .. } => 0,
    });
    out
}

/// Read who is using (and has used) the camera and microphone.
pub fn scan(engine: Option<&crate::engine::Engine>) -> AvReport {
    #[cfg(windows)]
    {
        let mut r = win::read();
        annotate(&mut r, engine);
        r
    }
    #[cfg(not(windows))]
    {
        let _ = engine;
        if std::env::var_os("BIMBO_GUARD_DEMO").is_some() {
            return demo();
        }
        AvReport { errors: vec!["Camera and microphone monitoring is only available on Windows".into()], ..Default::default() }
    }
}

/// Extra checks for apps that are using a device right now.
#[cfg_attr(not(windows), allow(dead_code))]
fn annotate(r: &mut AvReport, engine: Option<&crate::engine::Engine>) {
    let visible = crate::system::processes_with_visible_windows();
    for e in r.entries.iter_mut().filter(|e| e.in_use && !e.packaged) {
        let Some(exe) = e.exe.clone() else { continue };
        let exe_s = exe.display().to_string();
        e.flags.extend(crate::startup::location_flags(&exe_s));
        match visible.get(&exe_s.to_ascii_lowercase()) {
            Some(true) => e.has_visible_window = Some(true),
            Some(false) => {
                e.has_visible_window = Some(false);
                e.flags.push("No visible window: it may be listening or watching in the background".into());
            }
            None => {}
        }
        if let Some(eng) = engine {
            if exe.is_file() {
                let mut sc = eng.scanner();
                if let crate::engine::ScanOutcome::Detected(d) = eng.scan_file(&mut sc, &exe) {
                    e.flags.push(format!("Program flagged: {} ({})", d.summary(), d.severity().label()));
                }
            } else if exe.is_absolute() {
                e.flags.push("Program file not found (deleted or hidden)".into());
            }
        }
    }
}

#[cfg(not(windows))]
fn demo() -> AvReport {
    let now = chrono::Local::now();
    let secs = now.timestamp();
    let mic_on = (secs / 15) % 2 == 0;
    let mk = |device, id: &str, name: &str, exe: Option<&str>, packaged, in_use, mins_ago: i64, flags: Vec<String>, vis| AvUse {
        device,
        app_id: id.into(),
        app_name: name.into(),
        exe: exe.map(PathBuf::from),
        packaged,
        in_use,
        last_start: Some(now - chrono::Duration::minutes(mins_ago)),
        last_stop: if in_use { None } else { Some(now - chrono::Duration::minutes(mins_ago - 3)) },
        flags,
        has_visible_window: vis,
    };
    let mut access = HashMap::new();
    access.insert("Camera".into(), "Allow".into());
    access.insert("Microphone".into(), "Allow".into());
    AvReport {
        entries: vec![
            mk(Device::Microphone, "C:#Users#me#AppData#Local#Temp#svc_audio.exe", "svc_audio.exe", Some(r"C:\Users\me\AppData\Local\Temp\svc_audio.exe"), false, mic_on, 1,
               vec!["Runs from a temporary folder".into(), "No visible window: it may be listening or watching in the background".into()], Some(false)),
            mk(Device::Camera, "C:#Program Files#Zoom#bin#Zoom.exe", "Zoom.exe", Some(r"C:\Program Files\Zoom\bin\Zoom.exe"), false, true, 4, vec![], Some(true)),
            mk(Device::Camera, "Microsoft.WindowsCamera_8wekyb3d8bbwe", "Microsoft.WindowsCamera", None, true, false, 300, vec![], None),
            mk(Device::Microphone, "C:#Program Files#Google#Chrome#Application#chrome.exe", "chrome.exe", Some(r"C:\Program Files\Google\Chrome\Application\chrome.exe"), false, false, 90, vec![], None),
        ],
        access_setting: access,
        errors: vec![],
    }
}

#[cfg(windows)]
mod win {
    use super::*;
    use winreg::RegKey;
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};

    const BASE: &str = r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore";

    fn entry(device: Device, k: &RegKey, id: &str, packaged: bool) -> Option<AvUse> {
        let start: u64 = k.get_value("LastUsedTimeStart").ok()?;
        let stop: u64 = k.get_value("LastUsedTimeStop").unwrap_or(0);
        let (exe, name) = if packaged { (None, packaged_name(id)) } else {
            let (p, n) = decode_nonpackaged(id);
            (Some(p), n)
        };
        Some(AvUse {
            device,
            app_id: id.to_string(),
            app_name: name,
            exe,
            packaged,
            in_use: start != 0 && stop == 0,
            last_start: filetime(start),
            last_stop: filetime(stop),
            flags: Vec::new(),
            has_visible_window: None,
        })
    }

    pub fn read() -> AvReport {
        let mut r = AvReport::default();
        let mut seen: HashMap<(Device, String), usize> = HashMap::new();
        for device in [Device::Camera, Device::Microphone] {
            for hive in [HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE] {
                let path = format!(r"{BASE}\{}", device.store_key());
                let Ok(root) = RegKey::predef(hive).open_subkey_with_flags(&path, KEY_READ) else { continue };
                if hive == HKEY_CURRENT_USER {
                    if let Ok(v) = root.get_value::<String, _>("Value") {
                        r.access_setting.insert(device.label().to_string(), v);
                    }
                }
                for name in root.enum_keys().flatten() {
                    let Ok(sub) = root.open_subkey_with_flags(&name, KEY_READ) else { continue };
                    let mut found = Vec::new();
                    if name.eq_ignore_ascii_case("NonPackaged") {
                        for prog in sub.enum_keys().flatten() {
                            if let Ok(pk) = sub.open_subkey_with_flags(&prog, KEY_READ) {
                                if let Some(e) = entry(device, &pk, &prog, false) {
                                    found.push(e);
                                }
                            }
                        }
                    } else if let Some(e) = entry(device, &sub, &name, true) {
                        found.push(e);
                    }
                    for e in found {
                        // The same app can appear under HKCU and HKLM; keep the newest.
                        match seen.get(&e.key()) {
                            Some(&i) => {
                                let old = &r.entries[i];
                                if e.in_use || (!old.in_use && e.last_start > old.last_start) {
                                    r.entries[i] = e;
                                }
                            }
                            None => {
                                seen.insert(e.key(), r.entries.len());
                                r.entries.push(e);
                            }
                        }
                    }
                }
            }
        }
        r.entries.sort_by(|a, b| (b.in_use, b.last_start).cmp(&(a.in_use, a.last_start)));
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(device: Device, id: &str, in_use: bool) -> AvUse {
        AvUse {
            device,
            app_id: id.into(),
            app_name: id.into(),
            exe: None,
            packaged: false,
            in_use,
            last_start: filetime(133_000_000_000_000_000),
            last_stop: if in_use { None } else { filetime(133_000_000_600_000_000) },
            flags: vec![],
            has_visible_window: None,
        }
    }

    #[test]
    fn decode_names() {
        let (p, n) = decode_nonpackaged("C:#Program Files#Zoom#bin#Zoom.exe");
        assert_eq!(p, PathBuf::from(r"C:\Program Files\Zoom\bin\Zoom.exe"));
        assert_eq!(n, "Zoom.exe");
        assert_eq!(packaged_name("Microsoft.WindowsCamera_8wekyb3d8bbwe"), "Microsoft.WindowsCamera");
    }

    #[test]
    fn filetime_epoch() {
        // 2024-01-01T00:00:00Z
        let t = filetime(133_485_408_000_000_000).unwrap().with_timezone(&chrono::Utc);
        assert_eq!(t.to_rfc3339(), "2024-01-01T00:00:00+00:00");
        assert!(filetime(0).is_none());
    }

    #[test]
    fn start_and_stop_events() {
        let off = AvReport { entries: vec![u(Device::Camera, "zoom", false)], ..Default::default() };
        let on = AvReport { entries: vec![u(Device::Camera, "zoom", true)], ..Default::default() };
        let c = diff(&off, &on);
        assert!(matches!(c.as_slice(), [AvChange::Started { device: Device::Camera, .. }]));
        let c = diff(&on, &off);
        match c.as_slice() {
            [AvChange::Stopped { seconds: Some(60), .. }] => {}
            other => panic!("{other:?}"),
        }
        assert!(diff(&on, &on).is_empty());
    }
}

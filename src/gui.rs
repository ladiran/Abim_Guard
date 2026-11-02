//! Desktop window.

use crate::config::{APP_NAME, Settings};
use crate::core::Core;
use crate::engine::{Detection, Severity};
use crate::quarantine::{self, QuarantineItem};
use crate::scan::{self, ScanProgress};
use crate::startup::{self, StartupEntry};
use crate::system::{self, DefenderStatus};
use crate::watcher::Realtime;
use crate::devmon::DeviceMonitor;
use crate::usb::Location;
use eframe::egui::{self, Color32, RichText};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const ACCENT: Color32 = Color32::from_rgb(232, 163, 61); // warm amber
const OK: Color32 = Color32::from_rgb(92, 184, 122);
const WARN: Color32 = Color32::from_rgb(232, 163, 61);
const BAD: Color32 = Color32::from_rgb(224, 86, 86);

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Dashboard,
    Scan,
    Realtime,
    Usb,
    Privacy,
    Quarantine,
    Startup,
    History,
    Settings,
    About,
}

pub struct GuiApp {
    core: Arc<Core>,
    tab: Tab,
    scan: Option<Arc<ScanProgress>>,
    realtime: Option<Realtime>,
    devmon: Option<DeviceMonitor>,
    show_internal: bool,
    alerts: Vec<(Detection, String)>,
    defender: Arc<Mutex<Option<DefenderStatus>>>,
    startup: Arc<Mutex<Option<Vec<StartupEntry>>>>,
    startup_busy: Arc<AtomicBool>,
    include_ms_tasks: bool,
    quarantine: Vec<QuarantineItem>,
    draft: Settings,
    new_folder: String,
    message: Arc<Mutex<Option<(String, bool)>>>,
    busy: Arc<AtomicBool>,
    start_minimized: bool,
    first_frame: bool,
    tray_on: bool,
    quitting: Arc<AtomicBool>,
    toggle_requested: Arc<AtomicBool>,
    told_about_tray: bool,
}

fn sev_color(s: Severity) -> Color32 {
    match s {
        Severity::Malicious => BAD,
        Severity::Test => Color32::from_rgb(120, 160, 230),
        Severity::Pua | Severity::Suspicious => WARN,
    }
}

impl GuiApp {
    pub fn new(cc: &eframe::CreationContext<'_>, core: Arc<Core>, start_minimized: bool) -> Self {
        let mut visuals = egui::Visuals::dark();
        visuals.selection.bg_fill = ACCENT.linear_multiply(0.6);
        visuals.hyperlink_color = ACCENT;
        cc.egui_ctx.set_visuals(visuals);
        cc.egui_ctx.all_styles_mut(|s| {
            s.spacing.item_spacing = egui::vec2(8.0, 7.0);
            s.spacing.button_padding = egui::vec2(12.0, 6.0);
        });

        let draft = core.settings();
        let mut app = Self {
            quarantine: quarantine::list(&core.paths),
            core: core.clone(),
            tab: Tab::Dashboard,
            scan: None,
            realtime: None,
            devmon: None,
            show_internal: false,
            alerts: Vec::new(),
            defender: Arc::new(Mutex::new(None)),
            startup: Arc::new(Mutex::new(None)),
            startup_busy: Arc::new(AtomicBool::new(false)),
            include_ms_tasks: false,
            draft,
            new_folder: String::new(),
            message: Arc::new(Mutex::new(None)),
            busy: Arc::new(AtomicBool::new(false)),
            start_minimized,
            first_frame: true,
            tray_on: false,
            quitting: Arc::new(AtomicBool::new(false)),
            toggle_requested: Arc::new(AtomicBool::new(false)),
            told_about_tray: false,
        };

        // Remember the window so the tray can show and hide it.
        {
            use raw_window_handle::{HasWindowHandle, RawWindowHandle};
            if let Ok(h) = cc.window_handle() {
                if let RawWindowHandle::Win32(w) = h.as_raw() {
                    crate::tray::set_main_window(w.hwnd.get());
                }
            }
        }
        let ctx = cc.egui_ctx.clone();
        let (quit, toggle) = (app.quitting.clone(), app.toggle_requested.clone());
        app.tray_on = crate::tray::start(move |ev| {
            match ev {
                crate::tray::TrayEvent::Open => crate::tray::show_main_window(),
                crate::tray::TrayEvent::TogglePause => toggle.store(true, Ordering::SeqCst),
                crate::tray::TrayEvent::Quit => {
                    quit.store(true, Ordering::SeqCst);
                    crate::tray::close_main_window();
                }
            }
            ctx.request_repaint();
        });
        app.refresh_defender();
        if core.settings().realtime_on_start {
            app.toggle_realtime();
        }
        if core.settings().device_monitor {
            app.devmon = Some(DeviceMonitor::start(core.clone(), true));
        }
        app
    }

    fn say(&self, text: impl Into<String>, ok: bool) {
        *self.message.lock().unwrap() = Some((text.into(), ok));
    }

    fn refresh_defender(&self) {
        let d = self.defender.clone();
        std::thread::spawn(move || {
            let s = system::defender_status();
            *d.lock().unwrap() = Some(s);
        });
    }

    fn toggle_realtime(&mut self) {
        if let Some(rt) = self.realtime.take() {
            rt.stop();
        } else {
            match Realtime::start(self.core.clone(), true) {
                Ok(rt) => self.realtime = Some(rt),
                Err(e) => self.say(format!("Could not start real-time protection: {e}"), false),
            }
        }
        crate::tray::set_paused(self.realtime.is_none());
    }

    fn start_scan(&mut self, label: &str, roots: Vec<PathBuf>) {
        if self.scan.as_ref().map(|s| !s.done.load(Ordering::Relaxed)).unwrap_or(false) {
            return;
        }
        let p = Arc::new(ScanProgress::default());
        *p.label.lock().unwrap() = label.to_string();
        let core = self.core.clone();
        let p2 = p.clone();
        std::thread::spawn(move || scan::run_scan(core, roots, p2, true));
        self.scan = Some(p);
        self.tab = Tab::Scan;
    }

    fn run_startup_audit(&self) {
        if self.startup_busy.swap(true, Ordering::SeqCst) {
            return;
        }
        let (core, out, busy, ms) = (self.core.clone(), self.startup.clone(), self.startup_busy.clone(), self.include_ms_tasks);
        std::thread::spawn(move || {
            let r = startup::audit(&core.engine(), ms);
            let concerning = r.iter().filter(|e| e.is_concerning()).count();
            core.log("startup", format!("Startup audit: {} entries, {} need a look", r.len(), concerning), None, None);
            *out.lock().unwrap() = Some(r);
            busy.store(false, Ordering::SeqCst);
        });
    }

    // ---------- pages ----------

    fn page_dashboard(&mut self, ui: &mut egui::Ui) {
        ui.heading("Protection overview");
        ui.add_space(6.0);

        let d = self.defender.lock().unwrap().clone();
        let status_row = |ui: &mut egui::Ui, name: &str, add: &mut dyn FnMut(&mut egui::Ui)| {
            ui.horizontal(|ui| {
                let r = ui.label(RichText::new(name).strong());
                let pad = 170.0 - r.rect.width();
                if pad > 0.0 {
                    ui.add_space(pad);
                }
                ui.vertical(|ui| add(ui));
            });
        };
        status_row(ui, "Microsoft Defender", &mut |ui| match &d {
            None => {
                ui.spinner();
                ui.label("checking...");
            }
            Some(s) if s.available => {
                if s.antivirus_enabled && s.realtime_enabled {
                    ui.colored_label(OK, format!("On. Signatures updated {}", s.signatures_updated));
                } else {
                    ui.colored_label(BAD, "Real-time protection is OFF. Turn it on in Windows Security.");
                }
            }
            Some(s) => {
                ui.colored_label(WARN, s.error.clone().unwrap_or_else(|| "Unknown".into()));
            }
        });
        let rt_text = match &self.realtime {
            Some(rt) => {
                let n = rt.watching.lock().unwrap().len();
                if n == 0 {
                    (WARN, "On, but no folders are being watched. Add some in Settings.".to_string())
                } else {
                    (OK, format!("Watching {n} folder(s). {} files checked", rt.files_checked.load(Ordering::Relaxed)))
                }
            }
            None => (WARN, "Off".to_string()),
        };
        status_row(ui, "Bimbo Guard real-time", &mut |ui| {
            ui.colored_label(rt_text.0, &rt_text.1);
        });
        let e = self.core.engine();
        status_row(ui, "Detection data", &mut |ui| {
            ui.label(format!("{} rules, {} known-bad hashes", e.rule_count, e.hash_count()));
        });
        let qn = self.quarantine.len();
        status_row(ui, "Quarantine", &mut |ui| {
            ui.label(format!("{qn} item(s)"));
        });
        if let Some(m) = &self.devmon {
            let u = m.usb.lock().unwrap().clone();
            let sm = u.summary();
            status_row(ui, "USB ports", &mut |ui| {
                if u.ports.is_empty() {
                    ui.colored_label(WARN, u.errors.first().cloned().unwrap_or_else(|| "No ports found".into()));
                } else {
                    ui.label(format!("{} built-in: {} in use, {} free", sm.built_in, sm.built_in_in_use, sm.built_in_free));
                }
            });
            let a = m.av.lock().unwrap().clone();
            let active: Vec<String> = a.active().map(|e| format!("{} by {}", e.device.label(), e.app_name)).collect();
            status_row(ui, "Camera & microphone", &mut |ui| {
                if !a.errors.is_empty() && a.entries.is_empty() {
                    ui.colored_label(WARN, &a.errors[0]);
                } else if active.is_empty() {
                    ui.colored_label(OK, "Not in use");
                } else {
                    ui.colored_label(BAD, format!("IN USE: {}", active.join(", ")));
                }
            });
        } else {
            status_row(ui, "USB & camera watch", &mut |ui| {
                ui.colored_label(WARN, "Off (turn on in Settings)");
            });
        }

        ui.add_space(14.0);
        ui.horizontal_wrapped(|ui| {
            if ui.button(RichText::new("Quick scan").strong()).clicked() {
                self.start_scan("Quick scan", scan::quick_scan_roots());
            }
            if ui.button("Startup audit").clicked() {
                self.tab = Tab::Startup;
                self.run_startup_audit();
            }
            if ui.button(if self.realtime.is_some() { "Pause real-time" } else { "Start real-time" }).clicked() {
                self.toggle_realtime();
            }
            if ui.button("Refresh Defender status").clicked() {
                *self.defender.lock().unwrap() = None;
                self.refresh_defender();
            }
        });

        if !self.alerts.is_empty() {
            ui.add_space(14.0);
            ui.colored_label(BAD, RichText::new("Real-time detections").strong());
            detection_table(ui, "rt_alerts", &self.alerts, &self.core, &self.message);
            if ui.button("Clear list").clicked() {
                self.alerts.clear();
            }
        }

        ui.add_space(18.0);
        ui.separator();
        ui.weak("Bimbo Guard is a second layer. Keep Microsoft Defender switched on: it blocks threats \
                 at the kernel level, which a user-mode program cannot do.");
    }

    fn page_scan(&mut self, ui: &mut egui::Ui) {
        ui.heading("Scan");
        let running = self.scan.as_ref().map(|s| !s.done.load(Ordering::Relaxed)).unwrap_or(false);
        ui.add_enabled_ui(!running, |ui| {
            ui.horizontal_wrapped(|ui| {
                if ui.button(RichText::new("Quick scan").strong()).on_hover_text("Downloads, Desktop, Documents, Temp, Startup and Public folders").clicked() {
                    self.start_scan("Quick scan", scan::quick_scan_roots());
                }
                if ui.button("Full scan").on_hover_text("Every internal drive. This can take a long time").clicked() {
                    self.start_scan("Full scan", system::fixed_drives());
                }
                if ui.button("Scan a folder...").clicked() {
                    if let Some(f) = rfd::FileDialog::new().pick_folder() {
                        self.start_scan("Folder scan", vec![f]);
                    }
                }
                if ui.button("Scan files...").clicked() {
                    if let Some(f) = rfd::FileDialog::new().pick_files() {
                        self.start_scan("File scan", f);
                    }
                }
            });
        });
        ui.add_space(8.0);

        let Some(p) = self.scan.clone() else {
            ui.weak("No scan run yet in this session.");
            return;
        };
        let scanned = p.scanned.load(Ordering::Relaxed);
        let mb = p.bytes.load(Ordering::Relaxed) as f64 / 1_048_576.0;
        let label = p.label.lock().unwrap().clone();
        ui.horizontal_wrapped(|ui| {
            if running {
                ui.spinner();
            }
            ui.strong(format!(
                "{label}: {scanned} files ({mb:.0} MB) in {:.0} s, {} skipped",
                p.elapsed_secs(),
                p.skipped.load(Ordering::Relaxed)
            ));
            if running && ui.button("Stop").clicked() {
                p.cancel.store(true, Ordering::SeqCst);
            }
        });
        if running {
            path_label(ui, &p.current.lock().unwrap().clone());
        }
        let results = p.results.lock().unwrap().clone();
        ui.add_space(6.0);
        if results.is_empty() {
            if !running {
                ui.colored_label(OK, "No threats found.");
            }
        } else {
            ui.colored_label(BAD, format!("{} detection(s)", results.len()));
            detection_table(ui, "scan_results", &results, &self.core, &self.message);
        }
    }

    fn page_realtime(&mut self, ui: &mut egui::Ui) {
        ui.heading("Real-time protection");
        ui.label("Files are checked a couple of seconds after they are saved into a watched folder or copied from a USB drive.");
        ui.add_space(6.0);
        if ui.button(if self.realtime.is_some() { "Pause real-time protection" } else { "Start real-time protection" }).clicked() {
            self.toggle_realtime();
        }
        ui.add_space(8.0);
        if let Some(rt) = &self.realtime {
            ui.strong("Currently watching");
            for f in rt.watching.lock().unwrap().iter() {
                path_label(ui, &f.display().to_string());
            }
            ui.label(format!("{} files checked since start", rt.files_checked.load(Ordering::Relaxed)));
        }
        ui.add_space(8.0);
        ui.weak("Change the folder list in Settings, then pause and start again.");
    }

    fn page_quarantine(&mut self, ui: &mut egui::Ui) {
        ui.heading("Quarantine");
        ui.label("Quarantined files are scrambled so they cannot run. Restore only if you are sure a file is safe.");
        if ui.button("Refresh").clicked() {
            self.quarantine = quarantine::list(&self.core.paths);
        }
        ui.add_space(6.0);
        if self.quarantine.is_empty() {
            ui.weak("Quarantine is empty.");
            return;
        }
        let mut refresh = false;
        {
            for it in &self.quarantine {
                card(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        let name = it.original_path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                        ui.strong(name);
                        ui.weak(it.quarantined_at.format("%Y-%m-%d %H:%M").to_string());
                        ui.scope(|ui| {
                            if ui.small_button("Restore").clicked() {
                                match quarantine::restore(&self.core.paths, &it.id, None) {
                                    Ok(p) => {
                                        self.core.log("quarantine", "Restored from quarantine".into(), Some(&p), None);
                                        *self.message.lock().unwrap() = Some((format!("Restored to {}", p.display()), true));
                                    }
                                    Err(e) => *self.message.lock().unwrap() = Some((format!("Restore failed: {e}"), false)),
                                }
                                refresh = true;
                            }
                            if ui.small_button("Delete permanently").clicked() {
                                match quarantine::delete(&self.core.paths, &it.id) {
                                    Ok(()) => self.core.log("quarantine", "Deleted permanently".into(), Some(&it.original_path), None),
                                    Err(e) => *self.message.lock().unwrap() = Some((format!("Delete failed: {e}"), false)),
                                }
                                refresh = true;
                            }
                        });
                    });
                    path_label(ui, &it.original_path.display().to_string());
                    ui.label(&it.reason);
                });
            }
        }
        if refresh {
            self.quarantine = quarantine::list(&self.core.paths);
        }
    }

    fn page_startup(&mut self, ui: &mut egui::Ui) {
        ui.heading("Startup audit");
        ui.label("Programs set to run automatically: registry Run keys, Startup folders, Winlogon and scheduled tasks.");
        ui.horizontal_wrapped(|ui| {
            let busy = self.startup_busy.load(Ordering::Relaxed);
            if ui.add_enabled(!busy, egui::Button::new("Run audit")).clicked() {
                self.run_startup_audit();
            }
            ui.checkbox(&mut self.include_ms_tasks, "Include Microsoft's own scheduled tasks");
            if busy {
                ui.spinner();
            }
        });
        ui.add_space(6.0);
        let data = self.startup.lock().unwrap().clone();
        let Some(entries) = data else {
            ui.weak("Not run yet.");
            return;
        };
        let concerning = entries.iter().filter(|e| e.is_concerning()).count();
        if concerning == 0 {
            ui.colored_label(OK, format!("{} entries, nothing unusual.", entries.len()));
        } else {
            ui.colored_label(WARN, format!("{} entries, {} worth a look (listed first).", entries.len(), concerning));
        }
        {
            for e in &entries {
                card(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        if e.is_concerning() {
                            ui.colored_label(WARN, RichText::new("Check").strong());
                        } else {
                            ui.colored_label(OK, "OK");
                        }
                        ui.strong(&e.name);
                        ui.weak(&e.location);
                    });
                    path_label(ui, &e.command);
                    if let Some(d) = &e.detection {
                        ui.colored_label(sev_color(d.severity()), format!("{}: {}", d.severity().label(), d.summary()));
                    }
                    for f in &e.flags {
                        ui.colored_label(WARN, f);
                    }
                });
            }
        }
    }

    fn page_history(&mut self, ui: &mut egui::Ui) {
        ui.heading("History");
        ui.horizontal_wrapped(|ui| {
            if ui.button("Open log folder").clicked() {
                system::open_folder(&self.core.paths.logs);
            }
        });
        let events = self.core.recent.lock().unwrap().clone();
        {
            for ev in events.iter().rev() {
                ui.horizontal_wrapped(|ui| {
                    ui.weak(ev.time.format("%Y-%m-%d %H:%M:%S").to_string());
                    let c = if ev.kind == "detection" { BAD } else { ui.visuals().text_color() };
                    ui.colored_label(c, RichText::new(&ev.kind).strong());
                    ui.label(&ev.message);
                });
                if let Some(p) = &ev.path {
                    path_label(ui, p);
                }
                ui.separator();
            }
        }
    }

    fn page_settings(&mut self, ui: &mut egui::Ui) {
        ui.heading("Settings");
        {
            ui.strong("Watched folders");
            let mut remove = None;
            for (i, f) in self.draft.watched_folders.iter().enumerate() {
                ui.horizontal_wrapped(|ui| {
                    if ui.small_button("Remove").clicked() {
                        remove = Some(i);
                    }
                    path_label(ui, &f.display().to_string());
                });
            }
            if let Some(i) = remove {
                self.draft.watched_folders.remove(i);
            }
            ui.horizontal_wrapped(|ui| {
                if ui.button("Add folder...").clicked() {
                    if let Some(f) = rfd::FileDialog::new().pick_folder() {
                        self.draft.watched_folders.push(f);
                    }
                }
                ui.text_edit_singleline(&mut self.new_folder);
                if ui.button("Add typed path").clicked() && !self.new_folder.trim().is_empty() {
                    self.draft.watched_folders.push(PathBuf::from(self.new_folder.trim()));
                    self.new_folder.clear();
                }
            });
            ui.add_space(8.0);
            ui.checkbox(&mut self.draft.watch_removable_drives, "Scan USB and other removable drives when plugged in");
            ui.checkbox(&mut self.draft.realtime_on_start, "Start real-time protection when the app opens");
            ui.checkbox(&mut self.draft.auto_quarantine, "Quarantine malicious files automatically (suspicious ones are only reported)");
            ui.checkbox(&mut self.draft.defender_second_opinion, "Ask Microsoft Defender for a second opinion on each detection");
            ui.checkbox(&mut self.draft.device_monitor, "Watch USB ports and camera/microphone use in real time");
            ui.checkbox(&mut self.draft.usb_popups, "Pop up when a USB device is plugged in");
            ui.checkbox(&mut self.draft.av_popups, "Notify me whenever any program switches the camera or microphone on");
            ui.checkbox(&mut self.draft.close_to_tray, "Keep running in the system tray when I close the window");
            ui.horizontal_wrapped(|ui| {
                ui.label("Largest file to pattern scan (MB)");
                ui.add(egui::DragValue::new(&mut self.draft.max_scan_mb).range(1..=2048));
            });

            ui.add_space(8.0);
            ui.strong("Excluded folders");
            let mut remove = None;
            for (i, f) in self.draft.exclusions.iter().enumerate() {
                ui.horizontal_wrapped(|ui| {
                    if ui.small_button("Remove").clicked() {
                        remove = Some(i);
                    }
                    path_label(ui, &f.display().to_string());
                });
            }
            if let Some(i) = remove {
                self.draft.exclusions.remove(i);
            }
            if ui.button("Add exclusion...").clicked() {
                if let Some(f) = rfd::FileDialog::new().pick_folder() {
                    self.draft.exclusions.push(f);
                }
            }

            ui.add_space(8.0);
            ui.horizontal_wrapped(|ui| {
                if ui.button(RichText::new("Save settings").strong()).clicked() {
                    match self.core.save_settings(self.draft.clone()) {
                        Ok(()) => {
                            let _ = self.core.reload_engine();
                            let want = self.draft.device_monitor;
                            if want && self.devmon.is_none() {
                                self.devmon = Some(DeviceMonitor::start(self.core.clone(), true));
                            } else if !want {
                                if let Some(m) = self.devmon.take() {
                                    m.stop();
                                }
                            }
                            self.say("Settings saved. Pause and restart real-time protection to apply folder changes.", true);
                        }
                        Err(e) => self.say(format!("Could not save: {e}"), false),
                    }
                }
                if ui.button("Undo changes").clicked() {
                    self.draft = self.core.settings();
                }
            });

            ui.add_space(12.0);
            ui.separator();
            ui.strong("Detection data");
            let eng = self.core.engine();
            ui.label(format!("{} rules loaded, {} known-bad hashes", eng.rule_count, eng.hash_count()));
            for err in &eng.rule_errors {
                ui.colored_label(BAD, format!("Rule file skipped: {err}"));
            }
            ui.horizontal_wrapped(|ui| {
                if ui.button("Open rules folder").clicked() {
                    system::open_folder(&self.core.paths.rules);
                }
                if ui.button("Reload rules and hashes").clicked() {
                    match self.core.reload_engine() {
                        Ok(e) => self.say(format!("Loaded {} rules, {} hashes", e.rule_count, e.hash_count()), true),
                        Err(e) => self.say(format!("Reload failed: {e}"), false),
                    }
                }
                if ui.button("Import hash list...").on_hover_text("A text or CSV file with SHA-256 hashes").clicked() {
                    if let Some(f) = rfd::FileDialog::new().pick_file() {
                        match crate::feeds::import_file(&self.core, &f) {
                            Ok(n) => self.say(format!("Added {n} new hashes"), true),
                            Err(e) => self.say(format!("Import failed: {e}"), false),
                        }
                    }
                }
            });
            ui.add_space(6.0);
            ui.label("Hash feed address (for example your MalwareBazaar export link, which needs a free abuse.ch Auth-Key)");
            ui.text_edit_singleline(&mut self.draft.hash_feed_url);
            let busy = self.busy.load(Ordering::Relaxed);
            ui.horizontal_wrapped(|ui| {
                if ui.add_enabled(!busy, egui::Button::new("Download feed now")).clicked() {
                    let url = self.draft.hash_feed_url.trim().to_string();
                    let (core, msg, b) = (self.core.clone(), self.message.clone(), self.busy.clone());
                    b.store(true, Ordering::SeqCst);
                    std::thread::spawn(move || {
                        let r = crate::feeds::download_feed(&core, &url);
                        *msg.lock().unwrap() = Some(match r {
                            Ok(n) => (format!("Feed downloaded: {n} new hashes"), true),
                            Err(e) => (format!("Feed failed: {e}"), false),
                        });
                        b.store(false, Ordering::SeqCst);
                    });
                }
                if busy {
                    ui.spinner();
                }
            });

            ui.add_space(12.0);
            ui.separator();
            ui.strong("Windows");
            let mut auto = crate::autostart::is_enabled();
            if ui.checkbox(&mut auto, "Start Bimbo Guard in the system tray when I sign in").changed() {
                if let Err(e) = crate::autostart::set(auto) {
                    self.say(format!("Could not change startup setting: {e}"), false);
                }
            }
            if crate::package::is_packaged() {
                ui.horizontal_wrapped(|ui| {
                    ui.weak("Windows also lists this under Settings > Apps > Startup.");
                    if ui.small_button("Open Startup settings").clicked() {
                        crate::package::open_startup_settings();
                    }
                });
            }
            if ui.button("Open app data folder").clicked() {
                system::open_folder(&self.core.paths.root);
            }
        }
    }
}

pub const DEVELOPER_NAME: &str = "Oladiran Johnson Abimbola";
pub const DEVELOPER_ADDRESS: &str = "Department of Physics, Faculty of Physical Sciences, Federal University of Lafia";
pub const DEVELOPER_EMAIL: &str = "abimbola.oladiran@science.fulafia.edu.ng";
pub const AI_STATEMENT: &str = "Anthropic's Claude was used to assist in building this application.";

impl GuiApp {
    fn page_usb(&mut self, ui: &mut egui::Ui) {
        ui.heading("USB ports");
        let Some(m) = &self.devmon else {
            ui.colored_label(WARN, "USB watch is off. Turn it on in Settings.");
            return;
        };
        let u = m.usb.lock().unwrap().clone();
        let feed = m.feed.lock().unwrap().clone();
        let sm = u.summary();
        for e in &u.errors {
            ui.colored_label(WARN, e);
        }
        ui.label("Updated every 2 seconds. A USB 3 socket counts once, even though Windows sees it as two ports.");
        ui.add_space(6.0);

        ui.horizontal_wrapped(|ui| {
            stat(ui, "Built-in ports", sm.built_in.to_string(), None);
            stat(ui, "In use", sm.built_in_in_use.to_string(), Some(if sm.built_in_in_use > 0 { ACCENT } else { OK }));
            stat(ui, "Free", sm.built_in_free.to_string(), Some(OK));
            stat(ui, "USB 3.x", sm.built_in_usb3.to_string(), None);
            stat(ui, "USB 2.0 only", sm.built_in_usb2_only.to_string(), None);
            stat(ui, "USB-C", sm.built_in_type_c.to_string(), None);
            if sm.hub_ports > 0 {
                stat(ui, "Hub/dock ports", format!("{} ({} used)", sm.hub_ports, sm.hub_ports_in_use), None);
            }
        });
        ui.add_space(8.0);

        let section = |ui: &mut egui::Ui, title: &str, loc: Location| {
            let ports: Vec<_> = u.ports.iter().filter(|p| p.location == loc).collect();
            if ports.is_empty() {
                return;
            }
            ui.strong(title);
            for p in ports {
                card(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.strong(&p.label);
                        let kind_col = if p.usb3 { Color32::from_rgb(110, 160, 235) } else { ui.visuals().text_color() };
                        ui.colored_label(kind_col, p.kind());
                        ui.weak(p.connector());
                        if p.in_use() {
                            ui.colored_label(ACCENT, "IN USE");
                        } else {
                            ui.colored_label(OK, "free");
                        }
                    });
                    if let Some(d) = &p.device {
                        ui.label(format!("{}  (ID {:04X}:{:04X})", d.name, d.vid, d.pid));
                        ui.weak(d.speed_text());
                    }
                    if let Some(w) = p.slow_link_warning() {
                        ui.colored_label(WARN, w);
                    }
                    if loc == Location::ExternalHub {
                        path_label(ui, &format!("on {}", p.hub_name));
                    }
                });
            }
            ui.add_space(6.0);
        };
        section(ui, "Ports on this computer", Location::BuiltIn);
        section(ui, "Ports on hubs, docks or monitors", Location::ExternalHub);
        ui.checkbox(&mut self.show_internal, format!("Show internal connections ({} in use, such as a built-in webcam or Bluetooth)", sm.internal_devices));
        if self.show_internal {
            section(ui, "Internal connections (not reachable from outside)", Location::Internal);
        }

        ui.add_space(6.0);
        ui.strong("Live USB activity");
        let usb_feed: Vec<_> = feed.iter().filter(|e| e.kind == "usb").rev().take(30).collect();
        if usb_feed.is_empty() {
            ui.weak("No changes since the app started. Plug something in to see it appear here.");
        }
        for e in usb_feed {
            ui.horizontal_wrapped(|ui| {
                ui.weak(e.time.format("%H:%M:%S").to_string());
                if e.warning {
                    ui.colored_label(WARN, &e.message);
                } else {
                    ui.label(&e.message);
                }
            });
        }
        ui.add_space(8.0);
        ui.weak("Windows reports whether a port is USB-C, but not whether a non-C port is full-size Type-A, Mini or Micro. \
                 Computers almost always use full-size Type-A for these. Which ports count as built-in comes from the \
                 computer's firmware; on a few machines it is wrong, so check \"internal connections\" if a count looks off.");
    }

    fn page_privacy(&mut self, ui: &mut egui::Ui) {
        ui.heading("Camera & microphone");
        let Some(m) = &self.devmon else {
            ui.colored_label(WARN, "Camera and microphone watch is off. Turn it on in Settings.");
            return;
        };
        let a = m.av.lock().unwrap().clone();
        let feed = m.feed.lock().unwrap().clone();
        for e in &a.errors {
            ui.colored_label(WARN, e);
        }
        ui.label("Checked every second. Any program that switches on the camera or microphone is shown here, whether or not you allowed it.");
        ui.horizontal_wrapped(|ui| {
            for d in ["Camera", "Microphone"] {
                if let Some(v) = a.access_setting.get(d) {
                    let allowed = v.eq_ignore_ascii_case("Allow");
                    ui.label(format!("{d} access in Windows:"));
                    ui.colored_label(if allowed { ui.visuals().text_color() } else { OK }, if allowed { "allowed" } else { "blocked" });
                    ui.add_space(12.0);
                }
            }
        });
        ui.add_space(6.0);

        let active: Vec<_> = a.active().cloned().collect();
        if active.is_empty() {
            card(ui, |ui| {
                ui.colored_label(OK, RichText::new("Camera and microphone are not in use").strong());
            });
        }
        let mut trust_change: Option<(String, bool)> = None;
        let trusted = self.core.settings().trusted_av_apps;
        for e in &active {
            card(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.colored_label(BAD, RichText::new(format!("{} ON", e.device.label())).strong());
                    ui.strong(&e.app_name);
                    if let Some(t) = e.last_start {
                        let secs = (chrono::Local::now() - t).num_seconds().max(0);
                        ui.weak(format!("since {} ({})", t.format("%H:%M:%S"), crate::av::duration_text(secs)));
                    }
                    if e.packaged {
                        ui.weak("Store app");
                    }
                });
                if let Some(p) = &e.exe {
                    path_label(ui, &p.display().to_string());
                }
                match e.has_visible_window {
                    Some(true) => {
                        ui.weak("Has a visible window");
                    }
                    _ => {}
                }
                for f in &e.flags {
                    ui.colored_label(WARN, f);
                }
                ui.horizontal_wrapped(|ui| {
                    let is_trusted = trusted.iter().any(|t| t.eq_ignore_ascii_case(&e.app_id));
                    if is_trusted {
                        ui.weak("Trusted: notifications for this app are marked trusted");
                        if ui.small_button("Stop trusting").clicked() {
                            trust_change = Some((e.app_id.clone(), false));
                        }
                    } else if ui.small_button("Trust this app").on_hover_text("Its notifications will say \"trusted\" instead of warning you. Use is still logged.").clicked() {
                        trust_change = Some((e.app_id.clone(), true));
                    }
                    if let Some(p) = &e.exe {
                        if p.exists() && ui.small_button("Scan this program").clicked() {
                            let p = p.clone();
                            self.start_scan("Program scan", vec![p]);
                        }
                    }
                });
            });
        }

        ui.add_space(8.0);
        ui.strong("Live activity");
        let av_feed: Vec<_> = feed.iter().filter(|e| e.kind != "usb").rev().take(30).collect();
        if av_feed.is_empty() {
            ui.weak("No camera or microphone activity since the app started.");
        }
        for e in av_feed {
            ui.horizontal_wrapped(|ui| {
                ui.weak(e.time.format("%H:%M:%S").to_string());
                if e.warning {
                    ui.colored_label(BAD, &e.message);
                } else {
                    ui.label(&e.message);
                }
            });
        }

        ui.add_space(8.0);
        ui.strong("Every app that has used them (Windows' own record)");
        for e in a.entries.iter().filter(|e| !e.in_use).take(60) {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(e.device.label()).strong());
                ui.label(&e.app_name);
                if let Some(t) = e.last_start {
                    ui.weak(format!("last used {}", t.format("%Y-%m-%d %H:%M")));
                }
                if let (Some(a1), Some(b1)) = (e.last_start, e.last_stop) {
                    ui.weak(format!("for {}", crate::av::duration_text((b1 - a1).num_seconds().max(0))));
                }
            });
        }

        if let Some((id, on)) = trust_change {
            let mut s = self.core.settings();
            s.trusted_av_apps.retain(|t| !t.eq_ignore_ascii_case(&id));
            if on {
                s.trusted_av_apps.push(id.to_ascii_lowercase());
            }
            self.draft.trusted_av_apps = s.trusted_av_apps.clone();
            let _ = self.core.save_settings(s);
        }

        ui.add_space(8.0);
        ui.weak("This uses the same record Windows uses for its privacy indicator, so it sees normal apps and most spyware. \
                 Malware with its own kernel driver could bypass it. Covering the camera when not in use is still wise.");
    }

    fn page_about(&mut self, ui: &mut egui::Ui) {
        ui.heading("Developer");
        ui.add_space(6.0);
        card(ui, |ui| {
            ui.label(RichText::new(APP_NAME).size(20.0).strong().color(ACCENT));
            ui.weak(format!("Version {}, companion malware scanner for Windows", env!("CARGO_PKG_VERSION")));
            ui.add_space(10.0);
            let row = |ui: &mut egui::Ui, k: &str, add: &mut dyn FnMut(&mut egui::Ui)| {
                ui.horizontal(|ui| {
                    let r = ui.label(RichText::new(k).strong());
                    let pad = 110.0 - r.rect.width();
                    if pad > 0.0 {
                        ui.add_space(pad);
                    }
                    ui.vertical(|ui| add(ui));
                });
            };
            row(ui, "Developer", &mut |ui| {
                ui.label(DEVELOPER_NAME);
            });
            row(ui, "Address", &mut |ui| {
                ui.label(DEVELOPER_ADDRESS);
            });
            row(ui, "Contact", &mut |ui| {
                ui.hyperlink_to(DEVELOPER_EMAIL, format!("mailto:{DEVELOPER_EMAIL}"));
            });
        });
        ui.add_space(8.0);
        card(ui, |ui| {
            ui.strong("AI assistance");
            ui.label(AI_STATEMENT);
        });
        ui.add_space(8.0);
        card(ui, |ui| {
            ui.strong("Built with");
            ui.label("YARA-X by VirusTotal (pattern matching), egui and eframe (interface), notify (file watching), and Microsoft Defender's MpCmdRun for second opinions.");
            ui.add_space(4.0);
            ui.weak("Released under the MIT licence.");
        });
    }
}

fn stat(ui: &mut egui::Ui, label: &str, value: String, color: Option<Color32>) {
    egui::Frame::group(ui.style()).inner_margin(egui::Margin::symmetric(12, 8)).corner_radius(6.0).show(ui, |ui| {
        ui.vertical(|ui| {
            let mut t = RichText::new(value).size(22.0).strong();
            if let Some(c) = color {
                t = t.color(c);
            }
            ui.label(t);
            ui.weak(label);
        });
    });
}

/// Small grey text that breaks anywhere, so long paths never run off-screen.
fn path_label(ui: &mut egui::Ui, text: &str) {
    let mut job = egui::text::LayoutJob::single_section(
        text.to_string(),
        egui::TextFormat {
            font_id: egui::FontId::proportional(12.5),
            color: ui.visuals().weak_text_color(),
            ..Default::default()
        },
    );
    job.wrap = egui::text::TextWrapping { break_anywhere: true, ..Default::default() };
    ui.add(egui::Label::new(job).wrap());
}

fn card<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::group(ui.style())
        .inner_margin(egui::Margin::same(10))
        .corner_radius(6.0)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

fn detection_table(
    ui: &mut egui::Ui,
    id: &str,
    rows: &[(Detection, String)],
    core: &Arc<Core>,
    message: &Arc<Mutex<Option<(String, bool)>>>,
) {
    let _ = id;
    {
        for (d, action) in rows {
            let s = d.severity();
            card(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.colored_label(sev_color(s), RichText::new(s.label()).strong());
                    let name = d.path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                    ui.strong(name);
                    ui.weak(action);
                    if d.path.exists() {
                        if ui.small_button("Quarantine").clicked() {
                            match quarantine::quarantine(&core.paths, &d.path, &d.sha256, &d.summary()) {
                                Ok(_) => {
                                    core.log("quarantine", "Quarantined by user".into(), Some(&d.path), None);
                                    *message.lock().unwrap() = Some(("File quarantined".into(), true));
                                }
                                Err(e) => *message.lock().unwrap() = Some((format!("Quarantine failed: {e}"), false)),
                            }
                        }
                        if ui.small_button("Show in folder").clicked() {
                            if let Some(parent) = d.path.parent() {
                                system::open_folder(parent);
                            }
                        }
                    }
                });
                path_label(ui, &d.path.display().to_string());
                for f in &d.findings {
                    ui.label(format!("{}: {}", f.name, f.description));
                }
                if let Some(df) = &d.defender {
                    ui.label(RichText::new(df).italics());
                }
            });
        }
    }
}

impl eframe::App for GuiApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        if self.first_frame {
            self.first_frame = false;
            crate::tray::set_paused(self.realtime.is_none());
            if self.start_minimized {
                if self.tray_on {
                    crate::tray::hide_main_window();
                } else {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
                }
            }
        }

        // Tray menu: pause or resume real-time protection.
        if self.toggle_requested.swap(false, Ordering::SeqCst) {
            self.toggle_realtime();
        }

        // Closing the window keeps protection running in the tray.
        if ctx.input(|i| i.viewport().close_requested())
            && self.tray_on
            && self.core.settings().close_to_tray
            && !self.quitting.load(Ordering::SeqCst)
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            crate::tray::hide_main_window();
            if !self.told_about_tray {
                self.told_about_tray = true;
                crate::system::notify(
                    "Bimbo Guard is still running",
                    "Protection continues in the system tray. Right-click the shield icon to open or quit.",
                    false,
                );
            }
        }

        // Pull in real-time detections.
        if let Some(rt) = &self.realtime {
            let mut new: Vec<_> = rt.alerts.lock().unwrap().drain(..).collect();
            if !new.is_empty() {
                self.quarantine = quarantine::list(&self.core.paths);
                self.alerts.append(&mut new);
            }
        }
        if let Some(p) = &self.scan {
            if p.done.load(Ordering::Relaxed) {
                self.quarantine = quarantine::list(&self.core.paths);
            }
        }

        egui::Panel::left("nav").exact_size(170.0).resizable(false).show(ui, |ui| {
            ui.add_space(10.0);
            ui.label(RichText::new(APP_NAME).size(19.0).strong().color(ACCENT));
            ui.weak("companion scanner");
            ui.add_space(14.0);
            let items = [
                (Tab::Dashboard, "Overview"),
                (Tab::Scan, "Scan"),
                (Tab::Realtime, "Real-time"),
                (Tab::Usb, "USB ports"),
                (Tab::Privacy, "Camera & mic"),
                (Tab::Quarantine, "Quarantine"),
                (Tab::Startup, "Startup audit"),
                (Tab::History, "History"),
                (Tab::Settings, "Settings"),
                (Tab::About, "Developer"),
            ];
            for (t, name) in items {
                let mut text = RichText::new(name).size(15.0);
                if t == Tab::Privacy {
                    if let Some(m) = &self.devmon {
                        let n = m.av.lock().unwrap().active().count();
                        if n > 0 {
                            text = RichText::new(format!("{name}  (ON)")).size(15.0).strong();
                            if self.tab != t {
                                text = text.color(BAD);
                            }
                        }
                    }
                }
                if t == Tab::Dashboard && !self.alerts.is_empty() {
                    text = RichText::new(format!("{name}  ({})", self.alerts.len())).size(15.0).strong();
                }
                if ui.selectable_label(self.tab == t, text).clicked() {
                    self.tab = t;
                    if t == Tab::Quarantine {
                        self.quarantine = quarantine::list(&self.core.paths);
                    }
                }
            }
            ui.add_space(20.0);
            let on = self.realtime.is_some();
            ui.colored_label(if on { OK } else { WARN }, if on { "Real-time: on" } else { "Real-time: off" });
        });

        let msg = self.message.lock().unwrap().clone();
        if let Some((text, ok)) = msg {
            egui::Panel::bottom("msg").show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.colored_label(if ok { OK } else { BAD }, text);
                    if ui.small_button("Dismiss").clicked() {
                        *self.message.lock().unwrap() = None;
                    }
                });
            });
        }

        egui::CentralPanel::default().show(ui, |ui| {
            let tab = self.tab;
            egui::ScrollArea::vertical()
                .id_salt(tab as u8)
                .auto_shrink([false, false])
                .show(ui, |ui| {
            ui.add_space(4.0);
            match tab {
                Tab::Dashboard => self.page_dashboard(ui),
                Tab::Scan => self.page_scan(ui),
                Tab::Realtime => self.page_realtime(ui),
                Tab::Usb => self.page_usb(ui),
                Tab::Privacy => self.page_privacy(ui),
                Tab::Quarantine => self.page_quarantine(ui),
                Tab::Startup => self.page_startup(ui),
                Tab::History => self.page_history(ui),
                Tab::Settings => self.page_settings(ui),
                Tab::About => self.page_about(ui),
            }
            ui.add_space(12.0);
                });
        });

        // Keep progress and counters moving.
        ctx.request_repaint_after(Duration::from_millis(500));
    }
}

impl Drop for GuiApp {
    fn drop(&mut self) {
        crate::tray::remove();
        if let Some(m) = self.devmon.take() {
            m.stop();
        }
        if let Some(rt) = self.realtime.take() {
            rt.stop();
        }
    }
}

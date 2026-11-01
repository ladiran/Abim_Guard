//! Background watch on USB ports and camera/microphone use.

use crate::av::{self, AvChange, AvReport};
use crate::core::Core;
use crate::usb::{self, UsbChange, UsbReport};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct LiveEvent {
    pub time: chrono::DateTime<chrono::Local>,
    pub kind: &'static str, // "usb" | "camera" | "microphone"
    pub message: String,
    pub warning: bool,
}

pub struct DeviceMonitor {
    pub usb: Arc<Mutex<UsbReport>>,
    pub av: Arc<Mutex<AvReport>>,
    pub feed: Arc<Mutex<Vec<LiveEvent>>>,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl DeviceMonitor {
    pub fn start(core: Arc<Core>, popups: bool) -> Self {
        let usb_state = Arc::new(Mutex::new(usb::scan()));
        let av_state = Arc::new(Mutex::new(av::scan(Some(&core.engine()))));
        let feed = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));

        {
            let u = usb_state.lock().unwrap();
            let s = u.summary();
            core.log(
                "usb",
                format!(
                    "USB watch started: {} built-in ports ({} USB 3.x, {} USB 2.0 only, {} USB-C), {} in use, {} free",
                    s.built_in, s.built_in_usb3, s.built_in_usb2_only, s.built_in_type_c, s.built_in_in_use, s.built_in_free
                ),
                None,
                None,
            );
            let a = av_state.lock().unwrap();
            for e in a.active() {
                core.log(
                    if e.device == av::Device::Camera { "camera" } else { "microphone" },
                    format!("{} already in use by {}", e.device.label(), e.app_name),
                    e.exe.as_deref(),
                    None,
                );
            }
        }

        let (u2, a2, f2, s2) = (usb_state.clone(), av_state.clone(), feed.clone(), stop.clone());
        let handle = std::thread::spawn(move || {
            let mut last_usb = Instant::now();
            while !s2.load(Ordering::Relaxed) {
                // Camera and microphone: every second.
                let new_av = av::scan(Some(&core.engine()));
                let changes = av::diff(&a2.lock().unwrap(), &new_av);
                *a2.lock().unwrap() = new_av;
                let settings = core.settings();
                for c in changes {
                    let (kind, warning, popup_ok) = match &c {
                        AvChange::Started { device, flags, app_id, .. } => (
                            if *device == av::Device::Camera { "camera" } else { "microphone" },
                            !flags.is_empty(),
                            !settings.trusted_av_apps.iter().any(|t| t.eq_ignore_ascii_case(app_id)),
                        ),
                        AvChange::Stopped { device, .. } => {
                            (if *device == av::Device::Camera { "camera" } else { "microphone" }, false, false)
                        }
                    };
                    let msg = c.message();
                    let path = match &c {
                        AvChange::Started { exe, .. } => exe.clone(),
                        _ => None,
                    };
                    core.log(kind, msg.clone(), path.as_deref(), warning.then_some("Warning"));
                    if popups && settings.av_popups && popup_ok {
                        crate::system::alert("Bimbo Guard: privacy alert", &msg);
                    }
                    push(&f2, kind, msg, warning);
                }

                // USB: every two seconds.
                if last_usb.elapsed() >= Duration::from_secs(2) {
                    last_usb = Instant::now();
                    let new_usb = usb::scan();
                    let changes = usb::diff(&u2.lock().unwrap(), &new_usb);
                    let warnings: Vec<String> = new_usb.ports.iter().filter_map(|p| p.slow_link_warning().map(|w| format!("{}: {w}", p.label))).collect();
                    *u2.lock().unwrap() = new_usb;
                    let summary = u2.lock().unwrap().summary();
                    for c in changes {
                        let mut msg = c.message();
                        if let UsbChange::Connected { location: usb::Location::BuiltIn, .. } | UsbChange::Disconnected { location: usb::Location::BuiltIn, .. } = &c {
                            msg.push_str(&format!(". Built-in ports now: {} in use, {} free", summary.built_in_in_use, summary.built_in_free));
                        }
                        core.log("usb", msg.clone(), None, None);
                        let is_connect = matches!(c, UsbChange::Connected { .. });
                        if popups && settings.usb_popups && is_connect {
                            crate::system::alert("Bimbo Guard: USB device connected", &msg);
                        }
                        push(&f2, "usb", msg, false);
                    }
                    for w in warnings {
                        let already = f2.lock().unwrap().iter().rev().take(20).any(|e| e.message == w);
                        if !already {
                            push(&f2, "usb", w, true);
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(1000));
            }
        });

        Self { usb: usb_state, av: av_state, feed, stop, handle: Some(handle) }
    }

    pub fn stop(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn push(feed: &Arc<Mutex<Vec<LiveEvent>>>, kind: &'static str, message: String, warning: bool) {
    let mut f = feed.lock().unwrap();
    f.push(LiveEvent { time: chrono::Local::now(), kind, message, warning });
    let n = f.len();
    if n > 300 {
        f.drain(0..n - 300);
    }
}

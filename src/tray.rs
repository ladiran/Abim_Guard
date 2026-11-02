//! System tray icon and tray notifications (Windows).
//!
//! The icon lives on its own thread with a hidden window, so it keeps working
//! while the main window is hidden. Notifications use the standard Windows
//! tray balloon, which Windows 10/11 shows as a small notification and which
//! respects the user's notification and Do Not Disturb settings.

use std::sync::OnceLock;

#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrayEvent {
    Open,
    TogglePause,
    Quit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Info,
    Warning,
}

type Handler = Box<dyn Fn(TrayEvent) + Send + Sync>;
static HANDLER: OnceLock<Handler> = OnceLock::new();

/// Show or hide the main window (stored by the GUI at start-up).
pub fn set_main_window(hwnd: isize) {
    #[cfg(windows)]
    win::MAIN.store(hwnd, std::sync::atomic::Ordering::SeqCst);
    #[cfg(not(windows))]
    let _ = hwnd;
}

/// Start the tray icon. Returns false if it could not be created
/// (not Windows, or no shell running).
pub fn start(handler: impl Fn(TrayEvent) + Send + Sync + 'static) -> bool {
    if HANDLER.set(Box::new(handler)).is_err() {
        return is_running();
    }
    #[cfg(windows)]
    {
        win::start()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

pub fn is_running() -> bool {
    #[cfg(windows)]
    {
        win::TRAY_HWND.load(std::sync::atomic::Ordering::SeqCst) != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Show a tray notification. Returns false when there is no tray icon,
/// so the caller can fall back to another way of telling the user.
pub fn notify(title: &str, text: &str, level: Level) -> bool {
    #[cfg(windows)]
    {
        win::push(win::Cmd::Notify { title: title.into(), text: text.into(), level })
    }
    #[cfg(not(windows))]
    {
        let _ = (title, text, level);
        false
    }
}

/// Update the tray tooltip and menu label to show whether protection is paused.
pub fn set_paused(paused: bool) {
    #[cfg(windows)]
    {
        win::push(win::Cmd::Paused(paused));
    }
    #[cfg(not(windows))]
    let _ = paused;
}

pub fn show_main_window() {
    #[cfg(windows)]
    win::show_main(true);
}

pub fn hide_main_window() {
    #[cfg(windows)]
    win::show_main(false);
}

/// Ask the main window to close for real (used by Quit).
pub fn close_main_window() {
    #[cfg(windows)]
    win::close_main();
}

#[cfg_attr(not(windows), allow(dead_code))]
fn dispatch(e: TrayEvent) {
    if let Some(h) = HANDLER.get() {
        h(e);
    }
}

/// Keep text within the limits of a tray notification.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn clip(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max_chars.saturating_sub(3)).collect();
        t.push_str("...");
        t
    }
}

#[cfg(windows)]
mod win {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
    use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, WPARAM};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::Shell::*;
    use windows_sys::Win32::UI::WindowsAndMessaging::*;

    pub static TRAY_HWND: AtomicIsize = AtomicIsize::new(0);
    pub static MAIN: AtomicIsize = AtomicIsize::new(0);
    static PAUSED: AtomicBool = AtomicBool::new(false);
    static QUEUE: Mutex<VecDeque<Cmd>> = Mutex::new(VecDeque::new());
    static TASKBAR_CREATED: AtomicIsize = AtomicIsize::new(0);

    const WM_TRAY: u32 = WM_APP + 1;
    const WM_WAKE: u32 = WM_APP + 2;
    const ID_OPEN: usize = 1;
    const ID_PAUSE: usize = 2;
    const ID_QUIT: usize = 3;

    pub enum Cmd {
        Notify { title: String, text: String, level: Level },
        Paused(bool),
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn copy_into(dst: &mut [u16], s: &str) {
        let w: Vec<u16> = s.encode_utf16().take(dst.len() - 1).collect();
        dst[..w.len()].copy_from_slice(&w);
        dst[w.len()] = 0;
    }

    pub fn push(cmd: Cmd) -> bool {
        let h = TRAY_HWND.load(Ordering::SeqCst);
        if h == 0 {
            return false;
        }
        QUEUE.lock().unwrap().push_back(cmd);
        unsafe { PostMessageW(h as HWND, WM_WAKE, 0, 0) != 0 }
    }

    pub fn show_main(show: bool) {
        let h = MAIN.load(Ordering::SeqCst);
        if h == 0 {
            return;
        }
        unsafe {
            if show {
                ShowWindow(h as HWND, SW_SHOW);
                ShowWindow(h as HWND, SW_RESTORE);
                SetForegroundWindow(h as HWND);
            } else {
                ShowWindow(h as HWND, SW_HIDE);
            }
        }
    }

    pub fn close_main() {
        let h = MAIN.load(Ordering::SeqCst);
        if h != 0 {
            unsafe {
                PostMessageW(h as HWND, WM_CLOSE, 0, 0);
            }
        }
    }

    fn base_data(hwnd: HWND) -> NOTIFYICONDATAW {
        let mut d: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
        d.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        d.hWnd = hwnd;
        d.uID = 1;
        d
    }

    fn tooltip() -> String {
        if PAUSED.load(Ordering::SeqCst) {
            "Bimbo Guard: real-time protection paused".into()
        } else {
            "Bimbo Guard: protection on".into()
        }
    }

    unsafe fn add_icon(hwnd: HWND) {
        unsafe {
            let mut d = base_data(hwnd);
            d.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
            d.uCallbackMessage = WM_TRAY;
            // Icon resource 1 is embedded by build.rs; fall back to the default.
            let module = GetModuleHandleW(std::ptr::null());
            let mut icon = LoadImageW(module, 1 as _, IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), 0) as HICON;
            if icon.is_null() {
                icon = LoadIconW(std::ptr::null_mut(), IDI_APPLICATION);
            }
            d.hIcon = icon;
            copy_into(&mut d.szTip, &tooltip());
            Shell_NotifyIconW(NIM_ADD, &d);
        }
    }

    unsafe fn show_menu(hwnd: HWND) {
        unsafe {
            let menu = CreatePopupMenu();
            if menu.is_null() {
                return;
            }
            let open = wide("Open Bimbo Guard");
            let pause = wide(if PAUSED.load(Ordering::SeqCst) {
                "Resume real-time protection"
            } else {
                "Pause real-time protection"
            });
            let quit = wide("Quit (stops all protection)");
            AppendMenuW(menu, MF_STRING, ID_OPEN, open.as_ptr());
            AppendMenuW(menu, MF_STRING, ID_PAUSE, pause.as_ptr());
            AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());
            AppendMenuW(menu, MF_STRING, ID_QUIT, quit.as_ptr());
            let mut pt = POINT { x: 0, y: 0 };
            GetCursorPos(&mut pt);
            // Needed so the menu closes when the user clicks elsewhere.
            SetForegroundWindow(hwnd);
            TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN, pt.x, pt.y, 0, hwnd, std::ptr::null());
            PostMessageW(hwnd, WM_NULL, 0, 0);
            DestroyMenu(menu);
        }
    }

    unsafe fn drain(hwnd: HWND) {
        let cmds: Vec<Cmd> = QUEUE.lock().unwrap().drain(..).collect();
        for c in cmds {
            let mut d = base_data(hwnd);
            match c {
                Cmd::Notify { title, text, level } => {
                    d.uFlags = NIF_INFO;
                    copy_into(&mut d.szInfoTitle, &clip(&title, 63));
                    copy_into(&mut d.szInfo, &clip(&text, 255));
                    d.dwInfoFlags = match level {
                        Level::Warning => NIIF_WARNING,
                        Level::Info => NIIF_INFO,
                    };
                }
                Cmd::Paused(p) => {
                    PAUSED.store(p, Ordering::SeqCst);
                    d.uFlags = NIF_TIP;
                    copy_into(&mut d.szTip, &tooltip());
                }
            }
            unsafe {
                Shell_NotifyIconW(NIM_MODIFY, &d);
            }
        }
    }

    unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
        unsafe {
            match msg {
                WM_TRAY => {
                    match lparam as u32 {
                        WM_LBUTTONUP | WM_LBUTTONDBLCLK | NIN_BALLOONUSERCLICK => dispatch(TrayEvent::Open),
                        WM_RBUTTONUP | WM_CONTEXTMENU => show_menu(hwnd),
                        _ => {}
                    }
                    0
                }
                WM_COMMAND => {
                    match wparam & 0xFFFF {
                        ID_OPEN => dispatch(TrayEvent::Open),
                        ID_PAUSE => dispatch(TrayEvent::TogglePause),
                        ID_QUIT => dispatch(TrayEvent::Quit),
                        _ => {}
                    }
                    0
                }
                WM_WAKE => {
                    drain(hwnd);
                    0
                }
                WM_DESTROY => {
                    let d = base_data(hwnd);
                    Shell_NotifyIconW(NIM_DELETE, &d);
                    TRAY_HWND.store(0, Ordering::SeqCst);
                    PostQuitMessage(0);
                    0
                }
                m if m != 0 && m as isize == TASKBAR_CREATED.load(Ordering::SeqCst) => {
                    // Explorer restarted: put the icon back.
                    add_icon(hwnd);
                    0
                }
                _ => DefWindowProcW(hwnd, msg, wparam, lparam),
            }
        }
    }

    pub fn start() -> bool {
        let (tx, rx) = std::sync::mpsc::channel::<bool>();
        std::thread::spawn(move || unsafe {
            let module = GetModuleHandleW(std::ptr::null());
            let class = wide("BimboGuardTrayWindow");
            let wc = WNDCLASSW {
                lpfnWndProc: Some(wndproc),
                hInstance: module,
                lpszClassName: class.as_ptr(),
                ..std::mem::zeroed()
            };
            RegisterClassW(&wc);
            let tb = wide("TaskbarCreated");
            TASKBAR_CREATED.store(RegisterWindowMessageW(tb.as_ptr()) as isize, Ordering::SeqCst);
            let title = wide("Bimbo Guard tray");
            let hwnd = CreateWindowExW(0, class.as_ptr(), title.as_ptr(), WS_OVERLAPPED, 0, 0, 0, 0, std::ptr::null_mut(), std::ptr::null_mut(), module, std::ptr::null());
            if hwnd.is_null() {
                let _ = tx.send(false);
                return;
            }
            add_icon(hwnd);
            TRAY_HWND.store(hwnd as isize, Ordering::SeqCst);
            let _ = tx.send(true);
            let mut msg: MSG = std::mem::zeroed();
            while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        });
        rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap_or(false)
    }

    /// Remove the icon when the process exits.
    pub fn remove() {
        let h = TRAY_HWND.swap(0, Ordering::SeqCst);
        if h != 0 {
            unsafe {
                let d = base_data(h as HWND);
                Shell_NotifyIconW(NIM_DELETE, &d);
            }
        }
    }
}

/// Take the icon out of the tray (call before the program exits).
pub fn remove() {
    #[cfg(windows)]
    win::remove();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clip_keeps_short_text_and_trims_long() {
        assert_eq!(clip("hello", 10), "hello");
        let long = "a".repeat(300);
        let c = clip(&long, 255);
        assert_eq!(c.chars().count(), 255);
        assert!(c.ends_with("..."));
    }
}

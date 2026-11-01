//! Windows integration: Microsoft Defender, removable drives, alerts.
//! On other systems these functions degrade gracefully so the engine can be
//! developed and tested anywhere.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Run a console program without flashing a window.
pub fn hidden_command(program: impl AsRef<std::ffi::OsStr>) -> Command {
    #[allow(unused_mut)]
    let mut c = Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        c.creation_flags(CREATE_NO_WINDOW);
    }
    c
}

#[derive(Clone, Debug, Default)]
pub struct DefenderStatus {
    pub available: bool,
    pub antivirus_enabled: bool,
    pub realtime_enabled: bool,
    pub signatures_updated: String,
    pub signature_version: String,
    pub error: Option<String>,
}

pub fn defender_status() -> DefenderStatus {
    if !cfg!(windows) {
        return DefenderStatus { error: Some("Not running on Windows".into()), ..Default::default() };
    }
    let script = "$s=Get-MpComputerStatus; [pscustomobject]@{av=[bool]$s.AntivirusEnabled; rt=[bool]$s.RealTimeProtectionEnabled; sig=$s.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd HH:mm'); ver=[string]$s.AntivirusSignatureVersion} | ConvertTo-Json -Compress";
    let out = hidden_command("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            match serde_json::from_str::<serde_json::Value>(text.trim()) {
                Ok(v) => DefenderStatus {
                    available: true,
                    antivirus_enabled: v["av"].as_bool().unwrap_or(false),
                    realtime_enabled: v["rt"].as_bool().unwrap_or(false),
                    signatures_updated: v["sig"].as_str().unwrap_or("").to_string(),
                    signature_version: v["ver"].as_str().unwrap_or("").to_string(),
                    error: None,
                },
                Err(_) => DefenderStatus { error: Some("Could not read Defender status".into()), ..Default::default() },
            }
        }
        Ok(o) => DefenderStatus {
            error: Some(format!(
                "Defender status unavailable: {}",
                String::from_utf8_lossy(&o.stderr).lines().next().unwrap_or("unknown error")
            )),
            ..Default::default()
        },
        Err(e) => DefenderStatus { error: Some(format!("PowerShell not available: {e}")), ..Default::default() },
    }
}

/// Newest MpCmdRun.exe on the machine.
pub fn find_mpcmdrun() -> Option<PathBuf> {
    let platform = PathBuf::from(r"C:\ProgramData\Microsoft\Windows Defender\Platform");
    let mut best: Option<PathBuf> = None;
    if let Ok(rd) = std::fs::read_dir(&platform) {
        let mut dirs: Vec<PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.join("MpCmdRun.exe").exists()).collect();
        dirs.sort_by_key(|p| version_key(p));
        best = dirs.pop().map(|d| d.join("MpCmdRun.exe"));
    }
    best.or_else(|| {
        let p = PathBuf::from(r"C:\Program Files\Windows Defender\MpCmdRun.exe");
        p.exists().then_some(p)
    })
}

fn version_key(p: &Path) -> Vec<u64> {
    p.file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.split(|c: char| !c.is_ascii_digit()).filter_map(|x| x.parse().ok()).collect())
        .unwrap_or_default()
}

/// Ask Defender about one file without letting it take action.
/// Returns Ok(None) when clean, Ok(Some(threat names)) when it detects something.
pub fn defender_scan(file: &Path) -> anyhow::Result<Option<String>> {
    let exe = find_mpcmdrun().ok_or_else(|| anyhow::anyhow!("MpCmdRun.exe not found"))?;
    let out = hidden_command(exe)
        .arg("-Scan")
        .arg("-ScanType")
        .arg("3")
        .arg("-File")
        .arg(file)
        .arg("-DisableRemediation")
        .output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let threats: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("Threat ") || l.starts_with("Threat\t") || l.starts_with("Threat:"))
        .filter_map(|l| l.split_once(':').map(|(_, v)| v.trim().to_string()))
        .filter(|v| !v.is_empty())
        .collect();
    match out.status.code() {
        Some(0) => Ok(None),
        Some(2) if !threats.is_empty() => Ok(Some(threats.join(", "))),
        Some(2) if text.to_ascii_lowercase().contains("found") && text.to_ascii_lowercase().contains("threat") => {
            Ok(Some("threat reported".into()))
        }
        Some(c) => anyhow::bail!("Defender scan could not complete (code {c})"),
        None => anyhow::bail!("Defender scan was interrupted"),
    }
}

/// Roots of USB sticks and other removable drives currently present.
pub fn removable_drives() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};
        const DRIVE_REMOVABLE: u32 = 2;
        let mask = unsafe { GetLogicalDrives() };
        let mut out = Vec::new();
        for i in 0..26u32 {
            if mask & (1 << i) == 0 {
                continue;
            }
            let letter = (b'A' + i as u8) as char;
            let root = format!("{letter}:\\");
            let wide: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();
            let t = unsafe { GetDriveTypeW(wide.as_ptr()) };
            if t == DRIVE_REMOVABLE {
                out.push(PathBuf::from(root));
            }
        }
        out
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

/// Fixed (internal) drives, for the full scan.
pub fn fixed_drives() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};
        const DRIVE_FIXED: u32 = 3;
        let mask = unsafe { GetLogicalDrives() };
        (0..26u32)
            .filter(|i| mask & (1 << i) != 0)
            .map(|i| format!("{}:\\", (b'A' + i as u8) as char))
            .filter(|root| {
                let wide: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();
                unsafe { GetDriveTypeW(wide.as_ptr()) == DRIVE_FIXED }
            })
            .map(PathBuf::from)
            .collect()
    }
    #[cfg(not(windows))]
    {
        vec![PathBuf::from("/")]
    }
}

/// A pop-up alert that works even when the main window is minimised.
pub fn alert(title: &str, text: &str) {
    #[cfg(windows)]
    {
        use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONWARNING, MB_OK, MB_SETFOREGROUND, MB_TOPMOST};
        let t: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
        let m: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
        let (t, m) = (t, m);
        std::thread::spawn(move || unsafe {
            MessageBoxW(std::ptr::null_mut(), m.as_ptr(), t.as_ptr(), MB_OK | MB_ICONWARNING | MB_TOPMOST | MB_SETFOREGROUND);
        });
    }
    #[cfg(not(windows))]
    {
        eprintln!("ALERT {title}: {text}");
    }
}

/// Open a folder in Explorer.
pub fn open_folder(p: &Path) {
    #[cfg(windows)]
    {
        let _ = Command::new("explorer.exe").arg(p).spawn();
    }
    #[cfg(not(windows))]
    {
        let _ = Command::new("xdg-open").arg(p).spawn();
    }
}

/// Download a URL with the curl.exe that ships with Windows 10 and 11.
pub fn download(url: &str, dest: &Path) -> anyhow::Result<()> {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        anyhow::bail!("the feed address must start with https://");
    }
    let curl = if cfg!(windows) { "curl.exe" } else { "curl" };
    let out = hidden_command(curl)
        .args(["-fsSL", "--max-time", "300", "-o"])
        .arg(dest)
        .arg(url)
        .output()?;
    if !out.status.success() {
        anyhow::bail!("download failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

/// Extract a zip with the tar.exe that ships with Windows 10 and 11.
pub fn unzip(zip: &Path, into: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(into)?;
    let tar = if cfg!(windows) { "tar.exe" } else { "bsdtar" };
    let out = hidden_command(tar).arg("-xf").arg(zip).arg("-C").arg(into).output()?;
    if !out.status.success() {
        anyhow::bail!("could not extract archive: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

/// For every running program: does it show at least one visible, titled
/// window? Keyed by lower-case full path. Used to spot programs that use the
/// camera or microphone with nothing on screen.
pub fn processes_with_visible_windows() -> std::collections::HashMap<String, bool> {
    #[cfg(windows)]
    {
        win_proc::scan()
    }
    #[cfg(not(windows))]
    {
        std::collections::HashMap::new()
    }
}

#[cfg(windows)]
mod win_proc {
    use std::collections::{HashMap, HashSet};
    use windows_sys::Win32::Foundation::{CloseHandle, HWND, INVALID_HANDLE_VALUE, LPARAM};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS};
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW};
    use windows_sys::Win32::UI::WindowsAndMessaging::{EnumWindows, GetWindowTextLengthW, GetWindowThreadProcessId, IsWindowVisible};

    unsafe extern "system" fn collect(hwnd: HWND, lparam: LPARAM) -> windows_sys::core::BOOL {
        unsafe {
            if IsWindowVisible(hwnd) != 0 && GetWindowTextLengthW(hwnd) > 0 {
                let mut pid = 0u32;
                GetWindowThreadProcessId(hwnd, &mut pid);
                let set = &mut *(lparam as *mut HashSet<u32>);
                set.insert(pid);
            }
        }
        1
    }

    pub fn scan() -> HashMap<String, bool> {
        let mut visible: HashSet<u32> = HashSet::new();
        unsafe {
            EnumWindows(Some(collect), &mut visible as *mut _ as LPARAM);
        }
        let mut out: HashMap<String, bool> = HashMap::new();
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap == INVALID_HANDLE_VALUE {
                return out;
            }
            let mut pe: PROCESSENTRY32W = std::mem::zeroed();
            pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            let mut ok = Process32FirstW(snap, &mut pe) != 0;
            while ok {
                let pid = pe.th32ProcessID;
                let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
                if !h.is_null() {
                    let mut buf = [0u16; 1024];
                    let mut len = buf.len() as u32;
                    if QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len) != 0 {
                        let path = String::from_utf16_lossy(&buf[..len as usize]).to_ascii_lowercase();
                        let v = out.entry(path).or_insert(false);
                        *v |= visible.contains(&pid);
                    }
                    CloseHandle(h);
                }
                ok = Process32NextW(snap, &mut pe) != 0;
            }
            CloseHandle(snap);
        }
        out
    }
}

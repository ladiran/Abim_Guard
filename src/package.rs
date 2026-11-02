//! Microsoft Store (MSIX) support.
//!
//! The same program runs either as a plain download or from the Store
//! package. When packaged, Windows gives it an identity, its own data folder,
//! and the official startup mechanism (Settings > Apps > Startup), which the
//! Store requires instead of writing to the registry Run key.

use std::path::PathBuf;

/// Id of the startup task declared in the package manifest.
#[cfg_attr(not(windows), allow(dead_code))]
pub const STARTUP_TASK_ID: &str = "BimboGuardStartup";

/// The package family name, when running from an MSIX package.
pub fn family_name() -> Option<String> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::Packaging::Appx::GetCurrentPackageFamilyName;
        let mut len: u32 = 0;
        // First call reports the needed length (or that there is no package).
        unsafe { GetCurrentPackageFamilyName(&mut len, std::ptr::null_mut()) };
        if len == 0 || len > 1024 {
            return None;
        }
        let mut buf = vec![0u16; len as usize];
        let rc = unsafe { GetCurrentPackageFamilyName(&mut len, buf.as_mut_ptr()) };
        if rc != 0 {
            return None;
        }
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        Some(String::from_utf16_lossy(&buf[..end]))
    }
    #[cfg(not(windows))]
    {
        None
    }
}

pub fn is_packaged() -> bool {
    family_name().is_some()
}

/// Where app data lives when packaged: the package's own LocalState folder,
/// which Windows removes cleanly on uninstall.
pub fn packaged_data_dir() -> Option<PathBuf> {
    let family = family_name()?;
    let local = dirs::data_local_dir()?;
    Some(local.join("Packages").join(family).join("LocalState").join("BimboGuard"))
}

/// When the Store version first runs, bring over settings, rules and hashes
/// from a previous plain-download install, so nothing has to be set up twice.
pub fn migrate_from_unpackaged(new_root: &std::path::Path) {
    let Some(old_root) = dirs::data_local_dir().map(|d| d.join("BimboGuard")) else { return };
    if !old_root.is_dir() || new_root.join("settings.json").exists() {
        return;
    }
    let _ = std::fs::create_dir_all(new_root.join("rules"));
    for f in ["settings.json", "known_bad_sha256.txt"] {
        let _ = std::fs::copy(old_root.join(f), new_root.join(f));
    }
    if let Ok(rd) = std::fs::read_dir(old_root.join("rules")) {
        for e in rd.flatten() {
            let _ = std::fs::copy(e.path(), new_root.join("rules").join(e.file_name()));
        }
    }
}

/// True when Windows launched this packaged app through its startup task
/// (the user signed in), so it should start quietly in the tray.
pub fn launched_at_sign_in() -> bool {
    #[cfg(windows)]
    {
        if !is_packaged() {
            return false;
        }
        use windows::ApplicationModel::Activation::ActivationKind;
        use windows::ApplicationModel::AppInstance;
        AppInstance::GetActivatedEventArgs()
            .and_then(|a| a.Kind())
            .map(|k| k == ActivationKind::StartupTask)
            .unwrap_or(false)
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartupState {
    Enabled,
    Disabled,
    /// Turned off by the user in Settings or Task Manager; only they can turn it back on.
    DisabledByUser,
    /// Blocked by policy or not supported on this device.
    Blocked,
}

#[cfg(windows)]
fn task() -> windows::core::Result<windows::ApplicationModel::StartupTask> {
    windows::ApplicationModel::StartupTask::GetAsync(&windows::core::HSTRING::from(STARTUP_TASK_ID))?.join()
}

#[cfg(windows)]
fn map(s: windows::ApplicationModel::StartupTaskState) -> StartupState {
    use windows::ApplicationModel::StartupTaskState as S;
    match s {
        S::Enabled | S::EnabledByPolicy => StartupState::Enabled,
        S::DisabledByUser => StartupState::DisabledByUser,
        S::DisabledByPolicy => StartupState::Blocked,
        _ => StartupState::Disabled,
    }
}

pub fn startup_state() -> StartupState {
    #[cfg(windows)]
    {
        task().and_then(|t| t.State()).map(map).unwrap_or(StartupState::Blocked)
    }
    #[cfg(not(windows))]
    {
        StartupState::Blocked
    }
}

/// Turn starting at sign-in on or off. Windows never lets an app override a
/// user who switched it off in Settings; that case is reported back.
pub fn set_startup(on: bool) -> anyhow::Result<StartupState> {
    #[cfg(windows)]
    {
        let t = task()?;
        if on {
            Ok(map(t.RequestEnableAsync()?.join()?))
        } else {
            t.Disable()?;
            Ok(map(t.State()?))
        }
    }
    #[cfg(not(windows))]
    {
        let _ = on;
        anyhow::bail!("only available on Windows")
    }
}

/// Open the Startup apps page in Windows Settings.
pub fn open_startup_settings() {
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("explorer.exe").arg("ms-settings:startupapps").spawn();
    }
}

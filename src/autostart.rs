//! "Open when I sign in". Plain download: the per-user Run key (no admin
//! needed). Microsoft Store version: Windows' startup task (see package.rs).

#[cfg_attr(not(windows), allow(dead_code))]
const VALUE: &str = "AbimGuard";
/// Name used before the app was renamed (Bimbo Guard).
#[cfg_attr(not(windows), allow(dead_code))]
const OLD_VALUE: &str = "BimboGuard";

#[cfg(windows)]
fn key() -> std::io::Result<winreg::RegKey> {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
    winreg::RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(r"Software\Microsoft\Windows\CurrentVersion\Run", KEY_READ | KEY_WRITE)
}

pub fn is_enabled() -> bool {
    if crate::package::is_packaged() {
        return crate::package::startup_state() == crate::package::StartupState::Enabled;
    }
    #[cfg(windows)]
    {
        let Ok(k) = key() else { return false };
        // Someone who ticked "open when I sign in" in the old version keeps
        // that choice, now pointing at this program.
        if k.get_value::<String, _>(OLD_VALUE).is_ok() {
            let _ = k.delete_value(OLD_VALUE);
            if let Ok(exe) = std::env::current_exe() {
                let _ = k.set_value(VALUE, &format!("\"{}\" --minimized", exe.display()));
            }
        }
        k.get_value::<String, _>(VALUE).is_ok()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

pub fn set(on: bool) -> anyhow::Result<()> {
    if crate::package::is_packaged() {
        use crate::package::StartupState;
        return match crate::package::set_startup(on)? {
            StartupState::DisabledByUser if on => anyhow::bail!(
                "starting at sign-in was switched off in Windows Settings. Turn Abim Guard on under Settings > Apps > Startup"
            ),
            StartupState::Blocked if on => anyhow::bail!("starting at sign-in is blocked on this computer by Windows policy"),
            _ => Ok(()),
        };
    }
    #[cfg(windows)]
    {
        let k = key()?;
        if on {
            let exe = std::env::current_exe()?;
            k.set_value(VALUE, &format!("\"{}\" --minimized", exe.display()))?;
        } else {
            let _ = k.delete_value(VALUE);
        }
        let _ = k.delete_value(OLD_VALUE);
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = on;
        anyhow::bail!("only available on Windows")
    }
}

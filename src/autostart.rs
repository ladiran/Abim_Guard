//! "Open when I sign in", using the per-user Run key (no admin needed).

#[cfg_attr(not(windows), allow(dead_code))]
const VALUE: &str = "BimboGuard";

#[cfg(windows)]
fn key() -> std::io::Result<winreg::RegKey> {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
    winreg::RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(r"Software\Microsoft\Windows\CurrentVersion\Run", KEY_READ | KEY_WRITE)
}

pub fn is_enabled() -> bool {
    #[cfg(windows)]
    {
        key().and_then(|k| k.get_value::<String, _>(VALUE)).is_ok()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

pub fn set(on: bool) -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        let k = key()?;
        if on {
            let exe = std::env::current_exe()?;
            k.set_value(VALUE, &format!("\"{}\" --minimized", exe.display()))?;
        } else {
            let _ = k.delete_value(VALUE);
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = on;
        anyhow::bail!("only available on Windows")
    }
}

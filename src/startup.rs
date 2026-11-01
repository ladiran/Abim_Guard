//! Startup audit: everything set to launch automatically, checked for the
//! tricks malware uses to survive a reboot.

use crate::engine::{Detection, Engine, ScanOutcome};
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct StartupEntry {
    pub location: String,
    pub name: String,
    pub command: String,
    #[allow(dead_code)]
    pub target: Option<PathBuf>,
    pub flags: Vec<String>,
    pub detection: Option<Detection>,
}

impl StartupEntry {
    pub fn is_concerning(&self) -> bool {
        !self.flags.is_empty() || self.detection.is_some()
    }
}

/// Expand %VARIABLES% in a Windows command string.
pub fn expand_env(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        if let Some(end) = after.find('%') {
            let var = &after[..end];
            match std::env::var(var) {
                Ok(v) if !var.is_empty() => out.push_str(&v),
                _ => {
                    out.push('%');
                    out.push_str(var);
                    out.push('%');
                }
            }
            rest = &after[end + 1..];
        } else {
            out.push_str(&rest[start..]);
            rest = "";
        }
    }
    out.push_str(rest);
    out
}

/// Pull the program path out of a command line.
pub fn command_target(cmd: &str) -> Option<PathBuf> {
    let cmd = expand_env(cmd.trim());
    if cmd.is_empty() {
        return None;
    }
    if let Some(r) = cmd.strip_prefix('"') {
        return r.split('"').next().map(PathBuf::from);
    }
    let lower = cmd.to_ascii_lowercase();
    for ext in [".exe", ".com", ".bat", ".cmd", ".vbs", ".js", ".ps1", ".lnk", ".scr"] {
        if let Some(i) = lower.find(ext) {
            return Some(PathBuf::from(&cmd[..i + ext.len()]));
        }
    }
    cmd.split_whitespace().next().map(PathBuf::from)
}

pub fn location_flags(target: &str) -> Vec<String> {
    let t = target.to_ascii_lowercase().replace('/', "\\");
    let mut f = Vec::new();
    let risky = [
        ("\\appdata\\local\\temp\\", "Runs from a temporary folder"),
        ("\\windows\\temp\\", "Runs from the Windows temp folder"),
        ("\\users\\public\\", "Runs from the shared Public folder"),
        ("\\downloads\\", "Runs straight from Downloads"),
        ("\\$recycle.bin\\", "Runs from the Recycle Bin"),
    ];
    for (needle, why) in risky {
        if t.contains(needle) {
            f.push(why.to_string());
        }
    }
    // Program sitting directly in C:\ProgramData (not in a vendor subfolder).
    if let Some(rest) = t.strip_prefix("c:\\programdata\\") {
        if !rest.contains('\\') {
            f.push("Program placed loose in C:\\ProgramData".into());
        }
    }
    f
}

fn command_flags(cmd: &str) -> Vec<String> {
    let c = cmd.to_ascii_lowercase();
    let mut f = Vec::new();
    if c.contains("powershell") || c.contains("pwsh") {
        if c.contains(" -enc") || c.contains(" -e ") || c.contains("encodedcommand") {
            f.push("Launches PowerShell with a hidden (encoded) command".into());
        }
        if c.contains("hidden") {
            f.push("Launches PowerShell in a hidden window".into());
        }
        if c.contains("http://") || c.contains("https://") || c.contains("downloadstring") {
            f.push("PowerShell fetches something from the internet at startup".into());
        }
    }
    if c.contains("mshta") && (c.contains("http") || c.contains("javascript:") || c.contains("vbscript:")) {
        f.push("mshta runs remote or inline script".into());
    }
    if c.contains("regsvr32") && c.contains("/i:http") {
        f.push("regsvr32 loads a script from the internet".into());
    }
    if c.contains("rundll32") && (c.contains("\\appdata\\") || c.contains("\\temp\\") || c.contains("javascript:")) {
        f.push("rundll32 loads code from a user or temp folder".into());
    }
    if (c.contains("wscript") || c.contains("cscript")) && c.contains("\\appdata\\") {
        f.push("Runs a script hidden in AppData".into());
    }
    f
}

fn finish(engine: &Engine, location: &str, name: String, command: String) -> StartupEntry {
    let target = command_target(&command);
    let mut flags = location_flags(&command);
    flags.extend(command_flags(&command));
    let mut detection = None;
    if let Some(t) = &target {
        // Only judge existence when we have a full path.
        if t.is_absolute() && !t.exists() {
            flags.push("Points to a file that no longer exists".into());
        } else if t.is_file() {
            let mut sc = engine.scanner();
            if let ScanOutcome::Detected(d) = engine.scan_file(&mut sc, t) {
                detection = Some(d);
            }
        }
    }
    flags.sort();
    flags.dedup();
    StartupEntry { location: location.into(), name, command, target, flags, detection }
}

pub fn audit(engine: &Engine, include_microsoft_tasks: bool) -> Vec<StartupEntry> {
    let mut out = Vec::new();

    #[cfg(windows)]
    {
        use winreg::RegKey;
        use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
        let keys = [
            (HKEY_CURRENT_USER, "HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (HKEY_CURRENT_USER, "HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (HKEY_LOCAL_MACHINE, "HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (HKEY_LOCAL_MACHINE, "HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (HKEY_LOCAL_MACHINE, "HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        ];
        for (hive, hname, path) in keys {
            if let Ok(k) = RegKey::predef(hive).open_subkey(path) {
                for (name, _) in k.enum_values().flatten() {
                    let cmd: String = k.get_value(&name).unwrap_or_default();
                    out.push(finish(engine, &format!("{hname}\\{path}"), name, cmd));
                }
            }
        }
        // Winlogon values that malware likes to append to.
        if let Ok(k) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon") {
            let shell: String = k.get_value("Shell").unwrap_or_default();
            let userinit: String = k.get_value("Userinit").unwrap_or_default();
            let mut e = finish(engine, "HKLM Winlogon", "Shell".into(), shell.clone());
            if !shell.trim().eq_ignore_ascii_case("explorer.exe") && !shell.is_empty() {
                e.flags.push("Windows shell is not plain explorer.exe".into());
            }
            out.push(e);
            let mut e = finish(engine, "HKLM Winlogon", "Userinit".into(), userinit.clone());
            let norm = userinit.trim().trim_end_matches(',').to_ascii_lowercase();
            if !norm.is_empty() && norm != r"c:\windows\system32\userinit.exe" {
                e.flags.push("Userinit has extra programs added".into());
            }
            out.push(e);
        }
    }

    // Startup folders.
    let mut folders = Vec::new();
    if let Some(d) = dirs::config_dir() {
        folders.push(d.join(r"Microsoft\Windows\Start Menu\Programs\Startup"));
    }
    if cfg!(windows) {
        folders.push(PathBuf::from(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"));
    }
    for f in folders {
        for e in std::fs::read_dir(&f).into_iter().flatten().flatten() {
            let p = e.path();
            let name = e.file_name().to_string_lossy().to_string();
            if name.eq_ignore_ascii_case("desktop.ini") {
                continue;
            }
            let cmd = format!("\"{}\"", p.display());
            out.push(finish(engine, &format!("Startup folder ({})", f.display()), name, cmd));
        }
    }

    // Scheduled tasks via PowerShell (column names stay English this way).
    if cfg!(windows) {
        let script = r#"Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object { [pscustomobject]@{ n = $_.TaskPath + $_.TaskName; a = (($_.Actions | Where-Object { $_.Execute } | ForEach-Object { ('"' + $_.Execute + '" ' + $_.Arguments).Trim() }) -join ' ; ') } } | ConvertTo-Json -Compress"#;
        if let Ok(o) = crate::system::hidden_command("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script])
            .output()
        {
            let text = String::from_utf8_lossy(&o.stdout);
            let v: serde_json::Value = serde_json::from_str(text.trim()).unwrap_or(serde_json::Value::Null);
            let list = match v {
                serde_json::Value::Array(a) => a,
                serde_json::Value::Object(_) => vec![v],
                _ => vec![],
            };
            for t in list {
                let name = t["n"].as_str().unwrap_or("").to_string();
                let cmd = t["a"].as_str().unwrap_or("").to_string();
                if cmd.is_empty() {
                    continue;
                }
                if !include_microsoft_tasks && name.starts_with(r"\Microsoft\") {
                    // Still keep it if the command itself looks hostile.
                    if command_flags(&cmd).is_empty() && location_flags(&cmd).is_empty() {
                        continue;
                    }
                }
                let first = cmd.split(" ; ").next().unwrap_or("").to_string();
                let mut e = finish(engine, "Scheduled task", name, first);
                e.command = cmd;
                out.push(e);
            }
        }
    }

    out.sort_by_key(|e| (!e.is_concerning(), e.location.clone(), e.name.clone()));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets() {
        assert_eq!(command_target("\"C:\\Program Files\\App\\a.exe\" --min").unwrap(), PathBuf::from("C:\\Program Files\\App\\a.exe"));
        assert_eq!(command_target("C:\\Program Files\\App\\a.exe /x").unwrap(), PathBuf::from("C:\\Program Files\\App\\a.exe"));
    }

    #[test]
    fn flags() {
        assert!(!command_flags("powershell -w hidden -enc SQBFAFgA").is_empty());
        assert!(!location_flags("C:\\Users\\x\\AppData\\Local\\Temp\\a.exe").is_empty());
        assert!(!location_flags("C:\\ProgramData\\svch0st.exe").is_empty());
        assert!(location_flags("C:\\ProgramData\\Vendor\\app.exe").is_empty());
        assert!(command_flags("\"C:\\Program Files\\OneDrive\\OneDrive.exe\" /background").is_empty());
    }
}

//! Adding known-bad SHA-256 hashes ("malware signatures") from files or an
//! online feed such as MalwareBazaar.

use crate::core::Core;
use crate::engine::parse_hash;
use std::collections::HashSet;
use std::io::Write;
use std::path::Path;

/// What an import did.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Imported {
    /// Fingerprints that were not in the list before.
    pub added: usize,
    /// Fingerprints found in the file, new or already known.
    pub found: usize,
}

impl Imported {
    pub fn describe(&self) -> String {
        if self.added == 0 {
            format!("Signatures are up to date: {} fingerprints checked, none new.", self.found)
        } else {
            format!("Signatures updated: {} new fingerprints added ({} in the list).", self.added, self.found)
        }
    }
}

/// Merge hashes from text into the local list.
fn merge_text(core: &Core, text: &str) -> anyhow::Result<Imported> {
    let existing: HashSet<[u8; 32]> = std::fs::read_to_string(&core.paths.hashes_file)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| parse_hash(l.trim()))
        .collect();
    let mut found = HashSet::new();
    for line in text.lines() {
        if let Some(h) = parse_hash(line.trim()) {
            found.insert(h);
        }
    }
    let new: Vec<_> = found.iter().filter(|h| !existing.contains(*h)).collect();
    if !new.is_empty() {
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&core.paths.hashes_file)?;
        for h in &new {
            writeln!(f, "{}", hex::encode(h))?;
        }
    }
    Ok(Imported { added: new.len(), found: found.len() })
}

fn read_any(core: &Core, file: &Path) -> anyhow::Result<Imported> {
    let bytes = std::fs::read(file)?;
    if bytes.starts_with(b"PK") {
        return import_zip(core, file);
    }
    merge_text(core, &String::from_utf8_lossy(&bytes))
}

fn import_zip(core: &Core, zip: &Path) -> anyhow::Result<Imported> {
    let tmp = core.paths.root.join("feed_tmp");
    let _ = std::fs::remove_dir_all(&tmp);
    crate::system::unzip(zip, &tmp)?;
    let mut total = Imported::default();
    for e in walkdir::WalkDir::new(&tmp).into_iter().flatten() {
        if e.file_type().is_file() {
            let text = String::from_utf8_lossy(&std::fs::read(e.path())?).to_string();
            let r = merge_text(core, &text)?;
            total.added += r.added;
            total.found += r.found;
        }
    }
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(total)
}

/// Load the new list into the engine, log it and remember the update time.
fn finish(core: &Core, r: Imported, source: &str) -> anyhow::Result<Imported> {
    if r.found == 0 {
        anyhow::bail!(
            "{source} contained no SHA-256 fingerprints. Check that the link is complete and that your Auth-Key is correct"
        );
    }
    core.log("hashes", format!("Signature update from {source}: {} new, {} in list", r.added, r.found), None, None);
    core.reload_engine()?;
    core.record_signature_update(r.added);
    Ok(r)
}

/// Import a text, CSV or zip file of SHA-256 hashes chosen by the user.
pub fn import_file(core: &Core, file: &Path) -> anyhow::Result<Imported> {
    let r = read_any(core, file)?;
    finish(core, r, "the file")
}

/// Download a hash feed (for example the MalwareBazaar export) and import it.
pub fn download_feed(core: &Core, url: &str) -> anyhow::Result<Imported> {
    let url = url.trim();
    if url.is_empty() {
        anyhow::bail!("paste your MalwareBazaar export link first");
    }
    let dest = core.paths.root.join("feed_download.bin");
    crate::system::download(url, &dest)?;
    let r = read_any(core, &dest);
    let _ = std::fs::remove_file(&dest);
    finish(core, r?, "the download")
}

/// The MalwareBazaar "recent" export link for an Auth-Key. The key stays on
/// this computer, in the user's own settings.
pub fn malwarebazaar_recent_url(auth_key: &str) -> Option<String> {
    let k = auth_key.trim();
    if k.len() < 16 || !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return None;
    }
    Some(format!("https://mb-api.abuse.ch/v2/files/exports/{k}/recent.csv"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_recent_link_only_from_plausible_keys() {
        assert_eq!(
            malwarebazaar_recent_url("  abcdef0123456789abcdef0123456789abcdef0123456789 ").as_deref(),
            Some("https://mb-api.abuse.ch/v2/files/exports/abcdef0123456789abcdef0123456789abcdef0123456789/recent.csv")
        );
        assert!(malwarebazaar_recent_url("short").is_none());
        assert!(malwarebazaar_recent_url("abcdef0123456789/../../evil").is_none());
        assert!(malwarebazaar_recent_url("").is_none());
    }

    #[test]
    fn import_counts_new_and_known_and_rejects_empty() {
        let dir = std::env::temp_dir().join(format!("abim-feed-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let core = Core::with_paths(crate::config::AppPaths::at(&dir).unwrap()).unwrap();
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let f = dir.join("list.csv");
        std::fs::write(&f, format!("# MalwareBazaar\n\"2026-11-27\",\"{a}\"\n\"2026-11-27\",\"{b}\"\n")).unwrap();
        let r = import_file(&core, &f).unwrap();
        assert_eq!(r, Imported { added: 2, found: 2 });
        assert!(core.signatures.lock().unwrap().last_update.is_some());
        let r = import_file(&core, &f).unwrap();
        assert_eq!(r, Imported { added: 0, found: 2 });
        std::fs::write(&f, "<html>Unauthorized</html>").unwrap();
        assert!(import_file(&core, &f).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

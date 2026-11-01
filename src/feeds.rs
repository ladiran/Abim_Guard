//! Adding known-bad SHA-256 hashes from files or an online feed.

use crate::core::Core;
use crate::engine::parse_hash;
use std::collections::HashSet;
use std::io::Write;
use std::path::Path;

/// Merge hashes from text into the local list. Returns how many were new.
pub fn merge_text(core: &Core, text: &str) -> anyhow::Result<usize> {
    let existing: HashSet<[u8; 32]> = std::fs::read_to_string(&core.paths.hashes_file)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| parse_hash(l.trim()))
        .collect();
    let mut new = HashSet::new();
    for line in text.lines() {
        if let Some(h) = parse_hash(line.trim()) {
            if !existing.contains(&h) {
                new.insert(h);
            }
        }
    }
    if !new.is_empty() {
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&core.paths.hashes_file)?;
        for h in &new {
            writeln!(f, "{}", hex::encode(h))?;
        }
    }
    core.log("hashes", format!("Added {} new known-bad hashes", new.len()), None, None);
    core.reload_engine()?;
    Ok(new.len())
}

pub fn import_file(core: &Core, file: &Path) -> anyhow::Result<usize> {
    let bytes = std::fs::read(file)?;
    if bytes.starts_with(b"PK") {
        return import_zip(core, file);
    }
    merge_text(core, &String::from_utf8_lossy(&bytes))
}

fn import_zip(core: &Core, zip: &Path) -> anyhow::Result<usize> {
    let tmp = core.paths.root.join("feed_tmp");
    let _ = std::fs::remove_dir_all(&tmp);
    crate::system::unzip(zip, &tmp)?;
    let mut total = 0;
    for e in walkdir::WalkDir::new(&tmp).into_iter().flatten() {
        if e.file_type().is_file() {
            let text = String::from_utf8_lossy(&std::fs::read(e.path())?).to_string();
            total += merge_text(core, &text)?;
        }
    }
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(total)
}

pub fn download_feed(core: &Core, url: &str) -> anyhow::Result<usize> {
    if url.is_empty() {
        anyhow::bail!("enter a feed address in Settings first");
    }
    let dest = core.paths.root.join("feed_download.bin");
    crate::system::download(url, &dest)?;
    let r = import_file(core, &dest);
    let _ = std::fs::remove_file(&dest);
    r
}

//! Quarantine: moves a file out of harm's way in a form that cannot run.
//!
//! The file bytes are XOR-scrambled with a fixed key, so the stored copy is
//! not a working program and other scanners will not keep flagging it.
//! Metadata sits next to it as JSON so it can be restored.

use crate::config::AppPaths;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const KEY: &[u8] = b"BimboGuard-quarantine-v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuarantineItem {
    pub id: String,
    pub original_path: PathBuf,
    pub sha256: String,
    pub reason: String,
    pub quarantined_at: chrono::DateTime<chrono::Local>,
    pub size: u64,
}

fn scramble(data: &mut [u8]) {
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= KEY[i % KEY.len()];
    }
}

fn blob_path(paths: &AppPaths, id: &str) -> PathBuf {
    paths.quarantine.join(format!("{id}.qbin"))
}
fn meta_path(paths: &AppPaths, id: &str) -> PathBuf {
    paths.quarantine.join(format!("{id}.json"))
}

pub fn quarantine(paths: &AppPaths, file: &Path, sha256: &str, reason: &str) -> anyhow::Result<QuarantineItem> {
    let mut data = std::fs::read(file)?;
    let size = data.len() as u64;
    scramble(&mut data);
    let now = chrono::Local::now();
    let id = format!("{}-{}", now.format("%Y%m%d%H%M%S%3f"), &sha256[..12.min(sha256.len())]);
    let item = QuarantineItem {
        id: id.clone(),
        original_path: file.to_path_buf(),
        sha256: sha256.to_string(),
        reason: reason.to_string(),
        quarantined_at: now,
        size,
    };
    std::fs::write(blob_path(paths, &id), &data)?;
    std::fs::write(meta_path(paths, &id), serde_json::to_string_pretty(&item)?)?;
    // Only remove the original once the safe copy exists.
    if let Err(e) = std::fs::remove_file(file) {
        let _ = std::fs::remove_file(blob_path(paths, &id));
        let _ = std::fs::remove_file(meta_path(paths, &id));
        anyhow::bail!("could not remove the original file ({e}). It may be in use or need administrator rights");
    }
    Ok(item)
}

pub fn list(paths: &AppPaths) -> Vec<QuarantineItem> {
    let mut items: Vec<QuarantineItem> = std::fs::read_dir(&paths.quarantine)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.path().extension().map(|x| x == "json").unwrap_or(false))
        .filter_map(|e| std::fs::read_to_string(e.path()).ok())
        .filter_map(|s| serde_json::from_str(&s).ok())
        .collect();
    items.sort_by(|a, b| b.quarantined_at.cmp(&a.quarantined_at));
    items
}

/// Put the file back where it came from (or to `dest` if given).
pub fn restore(paths: &AppPaths, id: &str, dest: Option<&Path>) -> anyhow::Result<PathBuf> {
    let meta: QuarantineItem = serde_json::from_str(&std::fs::read_to_string(meta_path(paths, id))?)?;
    let target = dest.map(Path::to_path_buf).unwrap_or(meta.original_path.clone());
    if target.exists() {
        anyhow::bail!("{} already exists; choose another location", target.display());
    }
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut data = std::fs::read(blob_path(paths, id))?;
    scramble(&mut data);
    std::fs::write(&target, &data)?;
    delete(paths, id)?;
    Ok(target)
}

pub fn delete(paths: &AppPaths, id: &str) -> anyhow::Result<()> {
    std::fs::remove_file(blob_path(paths, id))?;
    std::fs::remove_file(meta_path(paths, id))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let base = std::env::temp_dir().join(format!("hg-q-{}", std::process::id()));
        let paths = AppPaths::at(&base).unwrap();
        let f = base.join("victim.bin");
        std::fs::write(&f, b"MZ pretend payload").unwrap();
        let item = quarantine(&paths, &f, "abcdef0123456789", "test").unwrap();
        assert!(!f.exists());
        let stored = std::fs::read(blob_path(&paths, &item.id)).unwrap();
        assert_ne!(&stored[..2], b"MZ");
        assert_eq!(list(&paths).len(), 1);
        restore(&paths, &item.id, None).unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"MZ pretend payload");
        assert!(list(&paths).is_empty());
        let _ = std::fs::remove_dir_all(&base);
    }
}

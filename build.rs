// 1. Scrambles the bundled detection rules so the finished program does not
//    contain the very text its own rules search for (otherwise Abim Guard,
//    or any other scanner, would flag abim-guard.exe as malware).
// 2. Embeds the icon and version details into the Windows .exe (winresource).

/// Must match `RULES_KEY` in src/engine.rs.
const RULES_KEY: &[u8] = b"bimbo-guard/rules/obfuscation-key/v1";

fn main() {
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());

    println!("cargo:rerun-if-changed=rules/core.yar");
    let mut rules = std::fs::read("rules/core.yar").expect("rules/core.yar is missing");
    for (i, b) in rules.iter_mut().enumerate() {
        *b ^= RULES_KEY[i % RULES_KEY.len()] ^ (i as u8).wrapping_mul(31);
    }
    std::fs::write(out_dir.join("core.yar.bin"), rules).unwrap();

    println!("cargo:rerun-if-changed=assets/abim-guard.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    // Works with the Windows SDK (rc.exe) and with MinGW (windres).
    let mut res = winresource::WindowsResource::new();
    res.set_icon("assets/abim-guard.ico")
        .set("FileDescription", "Abim Guard companion malware scanner")
        .set("ProductName", "Abim Guard")
        .set("OriginalFilename", "abim-guard.exe")
        .set("CompanyName", "Oladiran Johnson Abimbola, Federal University of Lafia")
        .set("LegalCopyright", "Copyright (c) 2026 Oladiran Johnson Abimbola. MIT License")
        .set("Comments", "Anthropic's Claude was used to assist in building this application.");
    if let Err(e) = res.compile() {
        println!("cargo:warning=could not embed icon and version details: {e}");
    }
}

fn require_one_of(candidates: &[std::path::PathBuf], label: &str, prep_scripts: &str) {
    if candidates.iter().any(|p| p.is_file()) {
        return;
    }
    panic!(
        "{} is missing (looked for {}). Run {} before a release build.",
        label,
        candidates
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(" or "),
        prep_scripts
    );
}

fn main() {
    println!("cargo:rerun-if-changed=icons/icon.ico");
    println!("cargo:rerun-if-changed=icons/32x32.png");
    println!("cargo:rerun-if-changed=icons/128x128.png");
    println!("cargo:rerun-if-changed=icons/128x128@2x.png");
    println!("cargo:rerun-if-changed=icons/MemHunter.png");
    let manifest = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let profile = std::env::var("PROFILE").unwrap_or_default();
    let skip = std::env::var("MEMHUNTER_SKIP_RUNTIME_RESOURCE").ok().as_deref() == Some("1");
    if profile == "release" && !skip {
        require_one_of(
            &[
                manifest.join("resources").join("runtime").join("python.exe"),
                manifest.join("resources").join("runtime").join("python"),
            ],
            "Bundled engine runtime",
            "scripts/windows/prepare-engine-runtime.ps1 or scripts/linux/prepare-engine-runtime.sh",
        );
        require_one_of(
            &[
                manifest
                    .join("resources")
                    .join("tools")
                    .join("bulk_extractor")
                    .join("bulk_extractor64.exe"),
                manifest
                    .join("resources")
                    .join("tools")
                    .join("bulk_extractor")
                    .join("bulk_extractor"),
            ],
            "Bundled bulk_extractor",
            "scripts/windows/prepare-bulk-extractor.ps1 or scripts/linux/prepare-bulk-extractor.sh",
        );
        require_one_of(
            &[
                manifest.join("resources").join("tools").join("capa").join("capa.exe"),
                manifest.join("resources").join("tools").join("capa").join("capa"),
            ],
            "Bundled capa",
            "scripts/windows/prepare-capa.ps1 or scripts/linux/prepare-capa.sh",
        );
        require_one_of(
            &[
                manifest.join("resources").join("tools").join("floss").join("floss.exe"),
                manifest.join("resources").join("tools").join("floss").join("floss"),
            ],
            "Bundled floss",
            "scripts/windows/prepare-floss.ps1 or scripts/linux/prepare-floss.sh",
        );
    }
    tauri_build::build()
}

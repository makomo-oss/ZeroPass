//! Builds the Tauri context.
//!
//! The user interface is built separately (`npm run build` in
//! `apps/desktop`) into `apps/desktop/dist`, which is embedded at compile
//! time. So that the Rust workspace builds and tests without Node.js, a
//! placeholder page is put there when it is missing; it says that the user
//! interface was not built. The package script builds the real one and
//! refuses the placeholder.

use std::path::Path;

/// Marks the placeholder page; `scripts/package-windows.ps1` looks for it.
const PLACEHOLDER_MARK: &str = "zeropass-ui-not-built";

fn main() {
    let dist = Path::new("../dist");
    let index = dist.join("index.html");
    if !index.exists() {
        std::fs::create_dir_all(dist).expect("cannot create ../dist");
        std::fs::write(
            &index,
            format!(
                "<!doctype html><meta charset=\"utf-8\"><title>ZeroPass</title>\
                 <meta name=\"{PLACEHOLDER_MARK}\">\
                 <p>The user interface was not built. Run <code>npm ci</code> and \
                 <code>npm run build</code> in <code>apps/desktop</code>, then build again.</p>"
            ),
        )
        .expect("cannot write the placeholder page");
    }
    println!("cargo:rerun-if-changed=../dist");
    tauri_build::build();
}

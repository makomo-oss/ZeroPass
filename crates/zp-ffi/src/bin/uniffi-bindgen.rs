//! Generates the Kotlin and Swift bindings from the compiled library:
//!
//! ```text
//! cargo run -p zp-ffi --features cli --bin uniffi-bindgen -- \
//!     generate --library <libzp_ffi> --language kotlin --out-dir <dir>
//! ```

fn main() {
    uniffi::uniffi_bindgen_main()
}

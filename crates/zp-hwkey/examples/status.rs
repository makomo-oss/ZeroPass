//! Reports whether this device has a usable hardware key store. Never prompts.
//!
//! ```text
//! cargo run -p zp-hwkey --example status
//! ```

fn main() {
    #[cfg(windows)]
    {
        let supported = zp_hwkey::windows_hello::WindowsHello::is_supported();
        eprintln!("Windows Hello set up for this user: {supported}");
        if supported {
            match zp_hwkey::windows_hello::WindowsHello::open() {
                Ok(_) => eprintln!("ZeroPass credential: exists (RSA, usable)"),
                Err(error) => eprintln!("ZeroPass credential: {error}"),
            }
        }
    }
    #[cfg(not(windows))]
    eprintln!("no hardware key store is implemented for this platform yet");
}

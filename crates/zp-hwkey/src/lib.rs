//! Platform hardware key stores for ZeroPass.
//!
//! The TOTP and passkey vault keys are wrapped by a key that never leaves the
//! platform's secure hardware and needs user verification for every use
//! (`docs/spec/crypto.md` §7). This crate provides the per-platform
//! implementations of [`zp_crypto::HardwareKeyStore`].
//!
//! | Platform | Implementation | Status |
//! |---|---|---|
//! | Windows | Windows Hello ([`windows_hello`]) | available |
//! | macOS / iOS | Secure Enclave | planned (P6-06, P6-09) |
//! | Android | Android Keystore | planned (P6-02, lives in the app) |
//! | Linux | TPM / fprintd | planned (P6-10) |

use zp_crypto::{HardwareKeyError, HardwareKeyStore};

#[cfg(windows)]
pub mod windows_hello;

/// Opens this platform's hardware key store.
///
/// With `create`, the underlying hardware key is created if it does not exist
/// yet, which may prompt the user. Returns [`HardwareKeyError::Unavailable`] on
/// platforms without an implementation or when the user has not set up
/// biometrics / a device PIN.
pub fn platform_key_store(create: bool) -> Result<Box<dyn HardwareKeyStore>, HardwareKeyError> {
    #[cfg(windows)]
    {
        use windows_hello::WindowsHello;
        let hello = if create {
            WindowsHello::open_or_create()?
        } else {
            WindowsHello::open()?
        };
        Ok(Box::new(hello.into_key_store()))
    }
    #[cfg(not(windows))]
    {
        let _ = create;
        Err(HardwareKeyError::Unavailable(
            "no hardware key store is implemented for this platform yet".into(),
        ))
    }
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;

    #[test]
    fn unsupported_platforms_report_unavailable() {
        assert!(matches!(
            platform_key_store(false),
            Err(HardwareKeyError::Unavailable(_))
        ));
        assert!(matches!(
            platform_key_store(true),
            Err(HardwareKeyError::Unavailable(_))
        ));
    }
}

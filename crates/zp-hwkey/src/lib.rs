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

use zeroize::Zeroizing;
use zp_crypto::{HardwareKeyError, HardwareKeyStore, UserVerifyingSigner};

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

/// This platform's user-verifying signing key, for a process that signs on
/// behalf of the one that wraps the keys (`docs/spec/ipc.md` §13).
pub struct PlatformSigner {
    signer: Box<dyn UserVerifyingSigner>,
    implementation_id: u8,
}

impl PlatformSigner {
    /// Which implementation this is: the first byte of the key slots wrapped
    /// with its signatures (`docs/spec/crypto.md` §7).
    pub fn implementation_id(&self) -> u8 {
        self.implementation_id
    }
}

impl UserVerifyingSigner for PlatformSigner {
    fn sign(&self, challenge: &[u8]) -> Result<Zeroizing<Vec<u8>>, HardwareKeyError> {
        self.signer.sign(challenge)
    }
}

impl core::fmt::Debug for PlatformSigner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PlatformSigner({:#04x})", self.implementation_id)
    }
}

/// Opens this platform's user-verifying signing key. `create` and the errors
/// are those of [`platform_key_store`].
pub fn platform_signer(create: bool) -> Result<PlatformSigner, HardwareKeyError> {
    #[cfg(windows)]
    {
        use windows_hello::WindowsHello;
        let hello = if create {
            WindowsHello::open_or_create()?
        } else {
            WindowsHello::open()?
        };
        Ok(PlatformSigner {
            signer: Box::new(hello),
            implementation_id: windows_hello::IMPLEMENTATION_ID,
        })
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

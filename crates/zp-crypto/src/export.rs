//! The key of an encrypted export (`docs/spec/export.md`): derived from a
//! passphrase the user chooses for that file, not from any vault key.
//!
//! ```text
//! ikm = Argon2id(UTF-8(NFKC(passphrase)), salt, m, t, p, 32 bytes)
//! key = HKDF-SHA256(salt = salt, ikm, info = "zeropass/v1/export")
//! ```
//!
//! The file is sealed with the envelope of `crypto.md` §4 under this key.

use core::fmt;

use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

use crate::kdf::{KDF_SALT_LEN, KdfParams, argon2id, hkdf_sha256};
use crate::secret::KEY_LEN;
use crate::{CryptoError, envelope};

const INFO_EXPORT: &[u8] = b"zeropass/v1/export";

/// The key that seals one export file.
pub struct ExportKey([u8; KEY_LEN]);

impl Drop for ExportKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for ExportKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExportKey(<redacted>)")
    }
}

impl ExportKey {
    /// Derives the key from the passphrase, the file's salt and its
    /// Argon2id parameters.
    pub fn derive(
        passphrase: &str,
        salt: &[u8; KDF_SALT_LEN],
        params: &KdfParams,
    ) -> Result<Self, CryptoError> {
        let normalized = Zeroizing::new(passphrase.nfkc().collect::<String>());
        let mut ikm = Zeroizing::new([0u8; KEY_LEN]);
        argon2id(params, normalized.as_bytes(), salt, &mut ikm)?;
        let mut key = Self([0u8; KEY_LEN]);
        hkdf_sha256(salt, ikm.as_slice(), INFO_EXPORT, &mut key.0)?;
        Ok(key)
    }

    /// Seals `plaintext`, bound to `aad` (the file's header).
    pub fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        envelope::seal(&self.0, aad, plaintext)
    }

    /// Opens what [`Self::seal`] sealed. A wrong passphrase, another header
    /// or a modified file all fail the same way.
    pub fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        envelope::open(&self.0, aad, sealed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> KdfParams {
        KdfParams::MINIMUM
    }

    #[test]
    fn what_is_sealed_opens_with_the_same_passphrase_only() {
        let salt = [7u8; KDF_SALT_LEN];
        let key = ExportKey::derive("a long export passphrase", &salt, &params()).unwrap();
        let sealed = key.seal(b"header", b"the vault").unwrap();
        assert_eq!(&*key.open(b"header", &sealed).unwrap(), b"the vault");
        // Another header, another passphrase, another salt.
        assert!(key.open(b"other", &sealed).is_err());
        let wrong = ExportKey::derive("another passphrase!!", &salt, &params()).unwrap();
        assert!(wrong.open(b"header", &sealed).is_err());
        let salted =
            ExportKey::derive("a long export passphrase", &[8u8; KDF_SALT_LEN], &params()).unwrap();
        assert!(salted.open(b"header", &sealed).is_err());
        let mut tampered = sealed.clone();
        if let Some(last) = tampered.last_mut() {
            *last ^= 1;
        }
        assert!(key.open(b"header", &tampered).is_err());
    }
}

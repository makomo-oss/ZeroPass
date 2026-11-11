//! Windows Hello as a hardware key store (`docs/spec/crypto.md` §7.1).
//!
//! A Windows Hello credential (`KeyCredentialManager`) is an RSA key held by the
//! TPM where one is present. It can only sign, and every signature shows the
//! Windows Hello prompt (fingerprint, face, or the Hello PIN). The signature over
//! a random challenge seeds the wrapping key; see
//! [`zp_crypto::SignatureKeyStore`].

use windows::Security::Credentials::{
    KeyCredential, KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
};
use windows::Security::Cryptography::CryptographicBuffer;
use windows::Storage::Streams::IBuffer;
use windows::core::{Array, HSTRING};
use zeroize::Zeroizing;
use zp_crypto::{HardwareKeyError, SignatureKeyStore, UserVerifyingSigner};

/// Blob implementation identifier of the Windows Hello key store.
pub const IMPLEMENTATION_ID: u8 = 0x02;

/// Name of the per-user Windows Hello credential shared by all ZeroPass vaults.
const CREDENTIAL_NAME: &str = "ZeroPass";

/// DER encoding of the `rsaEncryption` object identifier (1.2.840.113549.1.1.1).
const RSA_OID: [u8; 11] = [
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
];

/// The key store type returned by [`WindowsHello::into_key_store`].
pub type WindowsHelloKeyStore = SignatureKeyStore<WindowsHello>;

fn platform(error: windows::core::Error) -> HardwareKeyError {
    HardwareKeyError::Platform(error.message())
}

fn status_error(status: KeyCredentialStatus) -> HardwareKeyError {
    match status {
        KeyCredentialStatus::UserCanceled | KeyCredentialStatus::UserPrefersPassword => {
            HardwareKeyError::UserCancelled
        }
        KeyCredentialStatus::NotFound => HardwareKeyError::Unavailable(
            "the ZeroPass Windows Hello credential does not exist".into(),
        ),
        KeyCredentialStatus::SecurityDeviceLocked => {
            HardwareKeyError::Platform("the security device is locked".into())
        }
        other => HardwareKeyError::Platform(format!("Windows Hello status {}", other.0)),
    }
}

fn buffer_bytes(buffer: &IBuffer) -> Result<Zeroizing<Vec<u8>>, HardwareKeyError> {
    let mut bytes = Array::<u8>::new();
    CryptographicBuffer::CopyToByteArray(buffer, &mut bytes).map_err(platform)?;
    Ok(Zeroizing::new(bytes.to_vec()))
}

/// The ZeroPass Windows Hello credential of the current user.
#[derive(Debug)]
pub struct WindowsHello {
    name: HSTRING,
}

impl WindowsHello {
    /// Whether Windows Hello is set up for the current user.
    pub fn is_supported() -> bool {
        KeyCredentialManager::IsSupportedAsync()
            .and_then(|operation| operation.join())
            .unwrap_or(false)
    }

    /// Opens the credential, creating it if this user has none yet. Creating it
    /// shows the Windows Hello prompt once.
    pub fn open_or_create() -> Result<Self, HardwareKeyError> {
        match Self::open() {
            Err(HardwareKeyError::Unavailable(_)) if Self::is_supported() => Self::create(),
            other => other,
        }
    }

    /// Opens the existing credential. Does not prompt.
    pub fn open() -> Result<Self, HardwareKeyError> {
        if !Self::is_supported() {
            return Err(HardwareKeyError::Unavailable(
                "Windows Hello is not set up for this user".into(),
            ));
        }
        let hello = Self {
            name: HSTRING::from(CREDENTIAL_NAME),
        };
        ensure_deterministic(&hello.credential()?)?;
        Ok(hello)
    }

    fn create() -> Result<Self, HardwareKeyError> {
        let name = HSTRING::from(CREDENTIAL_NAME);
        let result = KeyCredentialManager::RequestCreateAsync(
            &name,
            KeyCredentialCreationOption::FailIfExists,
        )
        .and_then(|operation| operation.join())
        .map_err(platform)?;
        match result.Status().map_err(platform)? {
            KeyCredentialStatus::Success | KeyCredentialStatus::CredentialAlreadyExists => {}
            status => return Err(status_error(status)),
        }
        Self::open()
    }

    /// Deletes the credential. Every vault slot wrapped with it becomes unusable.
    pub fn delete() -> Result<(), HardwareKeyError> {
        KeyCredentialManager::DeleteAsync(&HSTRING::from(CREDENTIAL_NAME))
            .and_then(|action| action.join())
            .map_err(platform)
    }

    fn credential(&self) -> Result<KeyCredential, HardwareKeyError> {
        let result = KeyCredentialManager::OpenAsync(&self.name)
            .and_then(|operation| operation.join())
            .map_err(platform)?;
        match result.Status().map_err(platform)? {
            KeyCredentialStatus::Success => result.Credential().map_err(platform),
            status => Err(status_error(status)),
        }
    }

    /// Turns the credential into a [`zp_crypto::HardwareKeyStore`].
    pub fn into_key_store(self) -> WindowsHelloKeyStore {
        SignatureKeyStore::new(self, IMPLEMENTATION_ID)
    }
}

/// The construction needs deterministic signatures. Windows Hello credentials are
/// RSA keys signing with RSASSA-PKCS1-v1_5, which is deterministic; refuse
/// anything else rather than wrap secrets that could never be unwrapped.
fn ensure_deterministic(credential: &KeyCredential) -> Result<(), HardwareKeyError> {
    let public_key = credential
        .RetrievePublicKeyWithDefaultBlobType()
        .map_err(platform)?;
    let public_key = buffer_bytes(&public_key)?;
    if is_rsa_public_key(&public_key) {
        Ok(())
    } else {
        Err(HardwareKeyError::Unavailable(
            "the Windows Hello credential is not an RSA key".into(),
        ))
    }
}

/// Whether a DER `SubjectPublicKeyInfo` declares the `rsaEncryption` algorithm.
fn is_rsa_public_key(subject_public_key_info: &[u8]) -> bool {
    // The algorithm identifier sits at the start of the structure, before the key.
    let head = &subject_public_key_info[..subject_public_key_info.len().min(32)];
    head.windows(RSA_OID.len()).any(|window| window == RSA_OID)
}

impl UserVerifyingSigner for WindowsHello {
    fn sign(&self, challenge: &[u8]) -> Result<Zeroizing<Vec<u8>>, HardwareKeyError> {
        let credential = self.credential()?;
        let data = CryptographicBuffer::CreateFromByteArray(challenge).map_err(platform)?;
        let result = credential
            .RequestSignAsync(&data)
            .and_then(|operation| operation.join())
            .map_err(platform)?;
        match result.Status().map_err(platform)? {
            KeyCredentialStatus::Success => buffer_bytes(&result.Result().map_err(platform)?),
            status => Err(status_error(status)),
        }
    }
}

#[cfg(test)]
mod tests {
    use zp_crypto::{Totp, VaultId, VaultKey};

    use super::*;

    #[test]
    fn rsa_keys_are_recognised_by_their_algorithm_identifier() {
        // SEQUENCE { SEQUENCE { OID rsaEncryption, NULL }, BIT STRING ... }
        let mut rsa = vec![0x30, 0x82, 0x01, 0x22, 0x30, 0x0D];
        rsa.extend_from_slice(&RSA_OID);
        rsa.extend_from_slice(&[0x05, 0x00, 0x03, 0x82, 0x01, 0x0F, 0x00]);
        rsa.extend_from_slice(&[0xAA; 270]);
        assert!(is_rsa_public_key(&rsa));

        // SEQUENCE { SEQUENCE { OID id-ecPublicKey, OID prime256v1 }, BIT STRING ... }
        let mut ec = vec![0x30, 0x59, 0x30, 0x13];
        ec.extend_from_slice(&[0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]);
        ec.extend_from_slice(&[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]);
        ec.extend_from_slice(&[0x03, 0x42, 0x00, 0x04]);
        ec.extend_from_slice(&[0xBB; 64]);
        assert!(!is_rsa_public_key(&ec));
        assert!(!is_rsa_public_key(&[]));

        // The identifier must be the declared algorithm, not bytes inside the key.
        let mut hidden = ec.clone();
        hidden.extend_from_slice(&RSA_OID);
        assert!(!is_rsa_public_key(&hidden));
    }

    #[test]
    fn status_codes_map_to_errors() {
        assert_eq!(
            status_error(KeyCredentialStatus::UserCanceled),
            HardwareKeyError::UserCancelled
        );
        assert_eq!(
            status_error(KeyCredentialStatus::UserPrefersPassword),
            HardwareKeyError::UserCancelled
        );
        assert!(matches!(
            status_error(KeyCredentialStatus::NotFound),
            HardwareKeyError::Unavailable(_)
        ));
        assert!(matches!(
            status_error(KeyCredentialStatus::UnknownError),
            HardwareKeyError::Platform(_)
        ));
    }

    #[test]
    fn support_can_be_queried_without_prompting() {
        // Only checks that the call works on this machine, whatever the answer.
        let _ = WindowsHello::is_supported();
    }

    /// Manual acceptance test of P1-13. Shows real Windows Hello prompts:
    ///
    /// ```text
    /// cargo test -p zp-hwkey -- --ignored --nocapture windows_hello_protects_the_totp_vault_key
    /// ```
    ///
    /// Approve the first prompts, then **cancel** when asked to: the test checks
    /// that the vault key cannot be unwrapped without verification.
    #[test]
    #[ignore = "interactive: needs Windows Hello and a person at the machine"]
    fn windows_hello_protects_the_totp_vault_key() {
        use subtle::ConstantTimeEq;

        assert!(
            WindowsHello::is_supported(),
            "Windows Hello is not set up on this machine"
        );
        let store = WindowsHello::open_or_create().unwrap().into_key_store();
        let vault_id = VaultId::generate().unwrap();
        let vault_key = VaultKey::<Totp>::generate().unwrap();

        eprintln!(">>> Prompt 1: APPROVE (wrapping the TOTP vault key)");
        let slot = vault_key.wrap_with_hardware(&store, &vault_id).unwrap();
        assert_eq!(slot[0], IMPLEMENTATION_ID);

        eprintln!(">>> Prompt 2: APPROVE (unwrapping)");
        let unwrapped = VaultKey::<Totp>::unwrap_with_hardware(&store, &vault_id, &slot).unwrap();
        assert!(
            bool::from(vault_key.ct_eq(&unwrapped)),
            "signatures are not deterministic"
        );

        eprintln!(">>> Prompt 3: CANCEL (unwrapping must fail without verification)");
        let error = VaultKey::<Totp>::unwrap_with_hardware(&store, &vault_id, &slot).unwrap_err();
        assert_eq!(
            error,
            zp_crypto::CryptoError::HardwareKey(HardwareKeyError::UserCancelled),
            "the prompt was not cancelled, or cancelling did not block the unwrap"
        );
    }
}

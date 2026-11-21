//! Passkeys as the vault keeps them: new credentials, their keys, and where
//! they are stored (the passkey domain, `docs/spec/passkey.md` §3).
//!
//! Every credential is discoverable: the vault holds everything needed to
//! sign for it, and finds it by relying party alone. Reading or writing a
//! credential needs the passkey domain unlocked, which only the vault
//! daemon's passkey worker ever has (ADR-0007), so the private keys are
//! never decrypted anywhere else.

use zp_crypto::{ItemId, Passkey};
use zp_vault::Vault;
use zp_vault::model::{Content, PasskeyCredential};

use crate::PasskeyError;
use crate::key::{Algorithm, CredentialKey};

/// Length of the credential identifiers ZeroPass makes: random, and at
/// least the 16 bytes (100 bits of entropy) WebAuthn asks of identifiers
/// that do not encode the credential.
pub const CREDENTIAL_ID_LEN: usize = 16;

/// The longest credential identifier WebAuthn allows (§4, "Credential ID").
pub const MAX_CREDENTIAL_ID_LEN: usize = 1023;

/// The longest user handle WebAuthn allows (§5.4.3).
pub const MAX_USER_HANDLE_LEN: usize = 64;

/// What a relying party asks a new credential to be for (WebAuthn's
/// `PublicKeyCredentialRpEntity` and `PublicKeyCredentialUserEntity`).
#[derive(Debug, Clone, Copy)]
pub struct Account<'a> {
    /// The relying party identifier, already checked against the page.
    pub rp_id: &'a str,
    /// The relying party's name, for display.
    pub rp_name: &'a str,
    /// The user handle (`user.id`): 1 to 64 bytes.
    pub user_handle: &'a [u8],
    /// The account name (`user.name`), for display.
    pub user_name: &'a str,
    /// The display name (`user.displayName`).
    pub user_display_name: &'a str,
}

/// A new credential: the record to store, and its key.
pub fn new_credential(
    account: &Account<'_>,
    algorithm: Algorithm,
) -> Result<(PasskeyCredential, CredentialKey), PasskeyError> {
    if account.user_handle.is_empty() || account.user_handle.len() > MAX_USER_HANDLE_LEN {
        return Err(PasskeyError::Invalid("the user handle is 1 to 64 bytes"));
    }
    let key = CredentialKey::generate(algorithm)?;
    let mut credential_id = vec![0u8; CREDENTIAL_ID_LEN];
    getrandom::fill(&mut credential_id).map_err(|_| PasskeyError::Random)?;
    let record = PasskeyCredential {
        rp_id: account.rp_id.to_owned(),
        rp_name: account.rp_name.to_owned(),
        user_handle: account.user_handle.to_vec(),
        user_name: account.user_name.to_owned(),
        user_display_name: account.user_display_name.to_owned(),
        credential_id,
        private_key: key.to_pkcs8()?.to_vec(),
        cose_algorithm: algorithm.cose(),
    };
    Ok((record, key))
}

/// The key of a stored credential.
pub fn key_of(credential: &PasskeyCredential) -> Result<CredentialKey, PasskeyError> {
    let algorithm =
        Algorithm::from_cose(credential.cose_algorithm).ok_or(PasskeyError::MalformedKey)?;
    CredentialKey::from_pkcs8(algorithm, &credential.private_key)
}

/// The credentials of `rp_id`: all of them, or with `allowed` not empty,
/// those whose identifier is in it. Ordered by account name.
pub fn find(
    vault: &mut Vault,
    rp_id: &str,
    allowed: &[Vec<u8>],
) -> Result<Vec<(ItemId, PasskeyCredential)>, PasskeyError> {
    let mut found: Vec<(ItemId, PasskeyCredential)> = vault
        .list::<Passkey>()?
        .into_iter()
        .filter_map(|(id, content)| match content {
            Content::Passkey(credential) => Some((id, credential)),
            _ => None,
        })
        .filter(|(_, credential)| {
            credential.rp_id == rp_id
                && (allowed.is_empty() || allowed.contains(&credential.credential_id))
        })
        .collect();
    found.sort_by(|(a, x), (b, y)| {
        x.user_name
            .to_lowercase()
            .cmp(&y.user_name.to_lowercase())
            .then_with(|| a.cmp(b))
    });
    Ok(found)
}

/// Stores a new credential. One of the same relying party and user handle
/// is replaced, as WebAuthn's authenticators do (§6.3.2): the relying party
/// has just bound that account to the new one. Returns the item.
pub fn save(vault: &mut Vault, credential: PasskeyCredential) -> Result<ItemId, PasskeyError> {
    let existing = find(vault, &credential.rp_id, &[])?
        .into_iter()
        .find(|(_, stored)| stored.user_handle == credential.user_handle);
    match existing {
        Some((id, _)) => {
            vault.update(id, credential)?;
            Ok(id)
        }
        None => Ok(vault.insert(credential)?),
    }
}

//! The authenticator: makes credentials and assertions
//! (`docs/spec/passkey.md` §4–§6).
//!
//! It runs where the passkey domain is unlocked (the vault daemon's passkey
//! worker) and is called once the user has been verified for this one
//! ceremony (Windows Hello, ADR-0010). Nothing it returns is secret: the
//! relying party receives all of it.

use sha2::{Digest, Sha256};
use zp_crypto::ItemId;
use zp_vault::Vault;
use zp_vault::model::PasskeyCredential;

use crate::PasskeyError;
use crate::cbor::Cbor;
use crate::client::{Caller, Ceremony};
use crate::credential::{
    Account, MAX_CREDENTIAL_ID_LEN, MAX_USER_HANDLE_LEN, find, key_of, new_credential, save,
};
use crate::key::Algorithm;

/// The AAGUID of ZeroPass: the same for every ZeroPass authenticator, so a
/// relying party can tell which provider keeps a passkey
/// (`4826244e-9eab-4432-8ad5-d2f3693fb8c5`).
pub const AAGUID: [u8; 16] = [
    0x48, 0x26, 0x24, 0x4e, 0x9e, 0xab, 0x44, 0x32, 0x8a, 0xd5, 0xd2, 0xf3, 0x69, 0x3f, 0xb8, 0xc5,
];

/// The most credential identifiers a request may list.
pub const MAX_LISTED_CREDENTIALS: usize = 64;

/// Bits of the authenticator data's flags (WebAuthn §6.1).
pub mod flags {
    /// User present.
    pub const UP: u8 = 0x01;
    /// User verified.
    pub const UV: u8 = 0x04;
    /// Backup eligible: the credential may exist on more than one device.
    pub const BE: u8 = 0x08;
    /// Backed up: it does now.
    pub const BS: u8 = 0x10;
    /// Attested credential data included.
    pub const AT: u8 = 0x40;
    /// Extension data included.
    pub const ED: u8 = 0x80;
}

/// SHA-256 of the relying party identifier, the start of the authenticator data.
pub fn rp_id_hash(rp_id: &str) -> [u8; 32] {
    Sha256::digest(rp_id.as_bytes()).into()
}

/// A credential's public part, as the authenticator data attests it.
#[derive(Debug, Clone, Copy)]
pub struct Attested<'a> {
    /// The authenticator's AAGUID.
    pub aaguid: &'a [u8; 16],
    /// The credential identifier.
    pub credential_id: &'a [u8],
    /// The credential public key as a COSE_Key.
    pub public_key: &'a [u8],
}

/// The authenticator data (WebAuthn §6.1): the RP ID hash, `flags`, the
/// signature counter, and for a new credential its attested data (in which
/// case `flags` must have [`flags::AT`]).
pub fn authenticator_data(
    rp_id: &str,
    flags: u8,
    sign_count: u32,
    attested: Option<Attested<'_>>,
) -> Vec<u8> {
    let mut data = Vec::with_capacity(
        37 + attested.map_or(0, |a| 18 + a.credential_id.len() + a.public_key.len()),
    );
    data.extend_from_slice(&rp_id_hash(rp_id));
    data.push(flags);
    data.extend_from_slice(&sign_count.to_be_bytes());
    if let Some(attested) = attested {
        data.extend_from_slice(attested.aaguid);
        // The identifier is at most 1023 bytes, which fits.
        data.extend_from_slice(&(attested.credential_id.len() as u16).to_be_bytes());
        data.extend_from_slice(attested.credential_id);
        data.extend_from_slice(attested.public_key);
    }
    data
}

/// The attestation object of "none" attestation (WebAuthn §6.5, §8.7):
/// `{"fmt": "none", "attStmt": {}, "authData": …}`, keys in canonical order.
pub fn attestation_object(authenticator_data: &[u8]) -> Vec<u8> {
    Cbor::new()
        .map(3)
        .text("fmt")
        .text("none")
        .text("attStmt")
        .map(0)
        .text("authData")
        .bytes(authenticator_data)
        .finish()
}

/// Whether the credentials of this vault are backed up now: whether another
/// device of the vault, not revoked, holds them too (ADR-0010).
fn backed_up(vault: &Vault) -> Result<bool, PasskeyError> {
    let registry = vault.registry()?;
    let own = vault.device_id();
    Ok(registry
        .records()
        .any(|record| record.device_id != own && !registry.is_revoked(&record.device_id)))
}

/// The flags of every credential and assertion: the user was present and
/// verified (Windows Hello), the credential is eligible for backup, and
/// whether it is backed up.
fn ceremony_flags(vault: &Vault) -> Result<u8, PasskeyError> {
    let mut bits = flags::UP | flags::UV | flags::BE;
    if backed_up(vault)? {
        bits |= flags::BS;
    }
    Ok(bits)
}

fn check_listed(ids: &[Vec<u8>]) -> Result<(), PasskeyError> {
    if ids.len() > MAX_LISTED_CREDENTIALS
        || ids
            .iter()
            .any(|id| id.is_empty() || id.len() > MAX_CREDENTIAL_ID_LEN)
    {
        return Err(PasskeyError::Invalid(
            "a request lists at most 64 credential identifiers of 1 to 1023 bytes",
        ));
    }
    Ok(())
}

/// What `navigator.credentials.create` asks of the authenticator.
#[derive(Debug, Clone, Copy)]
pub struct CreateRequest<'a> {
    /// The frame's origin, as the browser reported it.
    pub origin: &'a str,
    /// The origin of the tab's top frame (empty: the frame is the top).
    pub top_origin: &'a str,
    /// `rp.id` (empty: the page's host).
    pub rp_id: &'a str,
    /// `rp.name`.
    pub rp_name: &'a str,
    /// `user.id`.
    pub user_handle: &'a [u8],
    /// `user.name`.
    pub user_name: &'a str,
    /// `user.displayName`.
    pub user_display_name: &'a str,
    /// `challenge`.
    pub challenge: &'a [u8],
    /// The algorithms of `pubKeyCredParams`, most preferred first.
    pub algorithms: &'a [i32],
    /// The identifiers of `excludeCredentials`.
    pub exclude: &'a [Vec<u8>],
}

/// A new credential, as the relying party receives it.
#[derive(Debug, Clone)]
pub struct Registration {
    /// The vault item that keeps it.
    pub item: ItemId,
    /// The credential identifier.
    pub credential_id: Vec<u8>,
    /// The client data JSON.
    pub client_data_json: Vec<u8>,
    /// The authenticator data, with the attested credential data.
    pub authenticator_data: Vec<u8>,
    /// The attestation object ("none").
    pub attestation_object: Vec<u8>,
    /// The public key as SubjectPublicKeyInfo.
    pub public_key: Vec<u8>,
    /// The algorithm of the key.
    pub algorithm: Algorithm,
}

/// Checks a request to create a credential before anything else is done:
/// the page, the relying party, the algorithm and the sizes. Returns the
/// relying party identifier and the algorithm.
pub fn check_create(request: &CreateRequest<'_>) -> Result<(String, Algorithm), PasskeyError> {
    let caller = Caller::new(request.origin, request.top_origin)?;
    let rp_id = caller.relying_party(request.rp_id)?;
    let algorithm =
        Algorithm::choose(request.algorithms).ok_or(PasskeyError::UnsupportedAlgorithm)?;
    if request.user_handle.is_empty() || request.user_handle.len() > MAX_USER_HANDLE_LEN {
        return Err(PasskeyError::Invalid("the user handle is 1 to 64 bytes"));
    }
    caller.client_data(Ceremony::Create, request.challenge)?;
    check_listed(request.exclude)?;
    Ok((rp_id, algorithm))
}

/// Makes a discoverable credential and keeps it in `vault` (WebAuthn §6.3.2,
/// with the client's part of §5.1.3). Fails with
/// [`PasskeyError::Excluded`] if the vault already holds one of the
/// credentials the relying party excludes.
pub fn make_credential(
    vault: &mut Vault,
    request: &CreateRequest<'_>,
) -> Result<Registration, PasskeyError> {
    let (rp_id, algorithm) = check_create(request)?;
    let caller = Caller::new(request.origin, request.top_origin)?;
    let client_data_json = caller.client_data(Ceremony::Create, request.challenge)?;
    if !request.exclude.is_empty() && !find(vault, &rp_id, request.exclude)?.is_empty() {
        return Err(PasskeyError::Excluded);
    }
    let account = Account {
        rp_id: &rp_id,
        rp_name: request.rp_name,
        user_handle: request.user_handle,
        user_name: request.user_name,
        user_display_name: request.user_display_name,
    };
    let (record, key) = new_credential(&account, algorithm)?;
    let public = key.public_key();
    let cose = public.to_cose();
    let authenticator_data = authenticator_data(
        &rp_id,
        ceremony_flags(vault)? | flags::AT,
        0,
        Some(Attested {
            aaguid: &AAGUID,
            credential_id: &record.credential_id,
            public_key: &cose,
        }),
    );
    let credential_id = record.credential_id.clone();
    let item = save(vault, record)?;
    Ok(Registration {
        item,
        credential_id,
        client_data_json,
        attestation_object: attestation_object(&authenticator_data),
        authenticator_data,
        public_key: public.to_spki(),
        algorithm,
    })
}

/// What `navigator.credentials.get` asks of the authenticator.
#[derive(Debug, Clone, Copy)]
pub struct GetRequest<'a> {
    /// The frame's origin, as the browser reported it.
    pub origin: &'a str,
    /// The origin of the tab's top frame (empty: the frame is the top).
    pub top_origin: &'a str,
    /// `rpId` (empty: the page's host).
    pub rp_id: &'a str,
    /// `challenge`.
    pub challenge: &'a [u8],
    /// The identifiers of `allowCredentials` (empty: any of the relying
    /// party's).
    pub allow: &'a [Vec<u8>],
    /// The credential the user picked among several, if any.
    pub chosen: Option<&'a [u8]>,
}

/// An assertion, as the relying party receives it.
#[derive(Debug, Clone)]
pub struct Assertion {
    /// The credential that signed.
    pub credential_id: Vec<u8>,
    /// The client data JSON.
    pub client_data_json: Vec<u8>,
    /// The authenticator data.
    pub authenticator_data: Vec<u8>,
    /// The signature over the authenticator data and the client data hash.
    pub signature: Vec<u8>,
    /// The credential's user handle.
    pub user_handle: Vec<u8>,
}

/// A credential the user may pick, for display. Nothing secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Choice {
    /// The credential identifier.
    pub credential_id: Vec<u8>,
    /// The account name.
    pub user_name: String,
    /// The display name.
    pub user_display_name: String,
}

/// The outcome of [`get_assertion`].
#[derive(Debug, Clone)]
pub enum GetOutcome {
    /// Signed with the one credential there was or that was picked.
    Signed(Assertion),
    /// Several credentials fit: the user picks one, and the request is made
    /// again with it.
    Choose(Vec<Choice>),
}

/// Checks a request for an assertion before anything else is done: the
/// page, the relying party, the challenge and the sizes. Returns the
/// relying party identifier.
pub fn check_get(request: &GetRequest<'_>) -> Result<String, PasskeyError> {
    let caller = Caller::new(request.origin, request.top_origin)?;
    let rp_id = caller.relying_party(request.rp_id)?;
    caller.client_data(Ceremony::Get, request.challenge)?;
    check_listed(request.allow)?;
    if request
        .chosen
        .is_some_and(|id| id.is_empty() || id.len() > MAX_CREDENTIAL_ID_LEN)
    {
        return Err(PasskeyError::Invalid(
            "a credential identifier is 1 to 1023 bytes",
        ));
    }
    Ok(rp_id)
}

/// Signs for the relying party with one of its credentials in `vault`
/// (WebAuthn §6.3.3, with the client's part of §5.1.4). Several fitting
/// credentials and none picked: the user is to choose.
pub fn get_assertion(
    vault: &mut Vault,
    request: &GetRequest<'_>,
) -> Result<GetOutcome, PasskeyError> {
    let rp_id = check_get(request)?;
    let caller = Caller::new(request.origin, request.top_origin)?;
    let candidates = find(vault, &rp_id, request.allow)?;
    let credential: PasskeyCredential = match (request.chosen, candidates.len()) {
        (_, 0) => return Err(PasskeyError::NoCredential),
        (Some(chosen), _) => candidates
            .into_iter()
            .find(|(_, credential)| credential.credential_id == chosen)
            .map(|(_, credential)| credential)
            .ok_or(PasskeyError::NoCredential)?,
        (None, 1) => candidates
            .into_iter()
            .map(|(_, credential)| credential)
            .next()
            .ok_or(PasskeyError::NoCredential)?,
        (None, _) => {
            return Ok(GetOutcome::Choose(
                candidates
                    .iter()
                    .map(|(_, credential)| Choice {
                        credential_id: credential.credential_id.clone(),
                        user_name: credential.user_name.clone(),
                        user_display_name: credential.user_display_name.clone(),
                    })
                    .collect(),
            ));
        }
    };
    let key = key_of(&credential)?;
    let client_data_json = caller.client_data(Ceremony::Get, request.challenge)?;
    let authenticator_data = authenticator_data(&rp_id, ceremony_flags(vault)?, 0, None);
    let signature = sign(&key, &authenticator_data, &client_data_json);
    Ok(GetOutcome::Signed(Assertion {
        credential_id: credential.credential_id.clone(),
        client_data_json,
        authenticator_data,
        signature,
        user_handle: credential.user_handle.clone(),
    }))
}

/// The assertion signature: over the authenticator data and the hash of the
/// client data (WebAuthn §6.3.3, step 11).
pub fn sign(
    key: &crate::CredentialKey,
    authenticator_data: &[u8],
    client_data_json: &[u8],
) -> Vec<u8> {
    let mut message = authenticator_data.to_vec();
    message.extend_from_slice(&Sha256::digest(client_data_json));
    key.sign(&message)
}

/// Checks an assertion as a relying party would, with the public key it got
/// at registration (as SubjectPublicKeyInfo): the signature over the
/// authenticator data and the client data hash.
pub fn verify(
    public_key: &[u8],
    authenticator_data: &[u8],
    client_data_json: &[u8],
    signature: &[u8],
) -> bool {
    let Ok(key) = crate::PublicKey::from_spki(public_key) else {
        return false;
    };
    let mut message = authenticator_data.to_vec();
    message.extend_from_slice(&Sha256::digest(client_data_json));
    key.verify(&message, signature)
}

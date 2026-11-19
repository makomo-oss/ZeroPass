//! WebAuthn `makeCredential` and `getAssertion` ceremonies
//! (`docs/spec/passkey.md` §4, ADR-0010).
//!
//! - `authenticatorData` flags: `UP=1`, `UV=1`, `BE=1`, `BS=1`, `AT=1` (registration)
//!   or `AT=0` (assertion), `ED=0`.
//! - `signCount`: fixed to `0` for offline-synced multi-device credentials.
//! - Attestation format: `"none"` with empty `attStmt` in CTAP2 canonical CBOR.

use ciborium::Value;
use sha2::{Digest, Sha256};
use zp_crypto::ItemId;
use zp_vault::Vault;

use crate::alg::{Algorithm, PublicKeyMaterial, encode_cbor, sign_raw, verify_raw};
use crate::error::PasskeyError;
use crate::store::{CreateParams, create_credential, find_credentials, load_for_signing};

/// ZeroPass authenticator AAGUID (`5a506173-7300-4000-8000-000000000001`).
pub const AAGUID: [u8; 16] = [
    0x5a, 0x50, 0x61, 0x73, 0x73, 0x00, 0x40, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

/// Authenticator data flag: User Present (bit 0).
pub const FLAG_UP: u8 = 0x01;
/// Authenticator data flag: User Verified (bit 2).
pub const FLAG_UV: u8 = 0x04;
/// Authenticator data flag: Backup Eligible (bit 3).
pub const FLAG_BE: u8 = 0x08;
/// Authenticator data flag: Backup State (bit 4).
pub const FLAG_BS: u8 = 0x10;
/// Authenticator data flag: Attested Credential Data included (bit 6).
pub const FLAG_AT: u8 = 0x40;

/// Flags for `makeCredential`: `UP | UV | BE | BS | AT` (`0x5D`).
pub const FLAGS_MAKE_CREDENTIAL: u8 = FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS | FLAG_AT;

/// Flags for `getAssertion`: `UP | UV | BE | BS` (`0x1D`).
pub const FLAGS_GET_ASSERTION: u8 = FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS;

/// Fixed signature counter (`0`) for multi-device syncable passkeys (ADR-0010).
pub const SIGN_COUNT: u32 = 0;

/// Length of an assertion `authenticatorData` without attested credential data
/// or extensions (`rpIdHash` 32 + `flags` 1 + `signCount` 4).
pub const ASSERTION_AUTH_DATA_LEN: usize = 37;

/// WebAuthn ceremony type for `clientDataJSON`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeremonyType {
    /// Registration (`"webauthn.create"`).
    Create,
    /// Authentication (`"webauthn.get"`).
    Get,
}

impl CeremonyType {
    /// The WebAuthn `CollectedClientData.type` string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "webauthn.create",
            Self::Get => "webauthn.get",
        }
    }
}

/// Computes `rpIdHash = SHA-256(UTF-8(rp_id))`.
pub fn rp_id_hash(rp_id: &str) -> [u8; 32] {
    let digest = Sha256::digest(rp_id.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Encodes `bytes` as URL-safe Base64 without padding (RFC 4648 §5).
pub fn base64url_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((bytes.len() * 4).div_ceil(3));
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = if chunk.len() > 1 {
            u32::from(chunk[1])
        } else {
            0
        };
        let b2 = if chunk.len() > 2 {
            u32::from(chunk[2])
        } else {
            0
        };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((triple >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((triple >> 6) & 0x3F) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(TABLE[(triple & 0x3F) as usize] as char);
        }
    }
    out
}

/// Builds WebAuthn `clientDataJSON` bytes and its SHA-256 hash (`clientDataHash`).
pub fn build_client_data_json(
    ceremony: CeremonyType,
    challenge: &[u8],
    origin: &str,
    cross_origin: bool,
) -> (Vec<u8>, [u8; 32]) {
    let challenge_b64 = base64url_encode(challenge);
    let escaped_origin = json_escape(origin);
    let json = format!(
        r#"{{"type":"{}","challenge":"{}","origin":"{}","crossOrigin":{}}}"#,
        ceremony.as_str(),
        challenge_b64,
        escaped_origin,
        cross_origin
    );
    let bytes = json.into_bytes();
    let digest = Sha256::digest(&bytes);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);
    (bytes, hash)
}

fn json_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => out.push_str(r#"\""#),
            '\\' => out.push_str(r"\\"),
            '\n' => out.push_str(r"\n"),
            '\r' => out.push_str(r"\r"),
            '\t' => out.push_str(r"\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!(r"\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// Builds `authenticatorData` for `makeCredential` (`AT=1`, `UP=1`, `UV=1`,
/// `BE=1`, `BS=1`, `signCount=0`).
pub fn build_registration_auth_data(
    rp_id: &str,
    credential_id: &[u8],
    cose_public_key: &[u8],
) -> Result<Vec<u8>, PasskeyError> {
    let cred_id_len = u16::try_from(credential_id.len()).map_err(|_| PasskeyError::Cbor)?;
    let mut auth_data = Vec::with_capacity(
        ASSERTION_AUTH_DATA_LEN + AAGUID.len() + 2 + credential_id.len() + cose_public_key.len(),
    );
    auth_data.extend_from_slice(&rp_id_hash(rp_id));
    auth_data.push(FLAGS_MAKE_CREDENTIAL);
    auth_data.extend_from_slice(&SIGN_COUNT.to_be_bytes());
    auth_data.extend_from_slice(&AAGUID);
    auth_data.extend_from_slice(&cred_id_len.to_be_bytes());
    auth_data.extend_from_slice(credential_id);
    auth_data.extend_from_slice(cose_public_key);
    Ok(auth_data)
}

/// Builds `authenticatorData` for `getAssertion` (`UP=1`, `UV=1`, `BE=1`,
/// `BS=1`, `AT=0`, `signCount=0`).
pub fn build_assertion_auth_data(rp_id: &str) -> [u8; ASSERTION_AUTH_DATA_LEN] {
    let mut auth_data = [0u8; ASSERTION_AUTH_DATA_LEN];
    auth_data[..32].copy_from_slice(&rp_id_hash(rp_id));
    auth_data[32] = FLAGS_GET_ASSERTION;
    auth_data[33..37].copy_from_slice(&SIGN_COUNT.to_be_bytes());
    auth_data
}

/// Builds a WebAuthn `"none"` `attestationObject` in CTAP2 canonical CBOR order
/// (`"fmt"`, `"attStmt"`, `"authData"`).
pub fn build_none_attestation_object(auth_data: &[u8]) -> Result<Vec<u8>, PasskeyError> {
    let map = Value::Map(vec![
        (Value::Text("fmt".into()), Value::Text("none".into())),
        (Value::Text("attStmt".into()), Value::Map(Vec::new())),
        (
            Value::Text("authData".into()),
            Value::Bytes(auth_data.to_vec()),
        ),
    ]);
    encode_cbor(&map)
}

/// Inputs to [`make_credential`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MakeCredentialRequest {
    /// Canonical relying party identifier (already validated against origin).
    pub rp_id: String,
    /// Relying party display name.
    pub rp_name: String,
    /// Opaque user handle (1..=64 bytes).
    pub user_handle: Vec<u8>,
    /// User account name.
    pub user_name: String,
    /// User display name.
    pub user_display_name: String,
    /// Preferred COSE algorithms in priority order.
    pub algorithms: Vec<i32>,
    /// Existing credential IDs that must not already exist for this RP.
    pub exclude_credential_ids: Vec<Vec<u8>>,
    /// SHA-256 hash of `clientDataJSON` (32 bytes).
    pub client_data_hash: [u8; 32],
}

/// Output of [`make_credential`]. Contains only public WebAuthn fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MakeCredentialResponse {
    /// Vault item identifier.
    pub item_id: ItemId,
    /// Generated 32-byte credential identifier.
    pub credential_id: Vec<u8>,
    /// Chosen COSE algorithm.
    pub algorithm: Algorithm,
    /// Public key material (COSE_Key CBOR and SPKI DER).
    pub public_key: PublicKeyMaterial,
    /// Raw `authenticatorData` bytes (with attested credential data).
    pub authenticator_data: Vec<u8>,
    /// CBOR-encoded `attestationObject` (`fmt: "none"`).
    pub attestation_object: Vec<u8>,
}

/// Executes WebAuthn `makeCredential`: generates and stores a passkey in the
/// vault's `Passkey` (`VK-K`) domain and returns the registration response
/// (`authenticatorData` and `"none"` `attestationObject`).
///
/// The caller must verify the user (UV) before invoking this function.
pub fn make_credential(
    vault: &mut Vault,
    request: &MakeCredentialRequest,
) -> Result<MakeCredentialResponse, PasskeyError> {
    let created = create_credential(
        vault,
        &CreateParams {
            rp_id: request.rp_id.clone(),
            rp_name: request.rp_name.clone(),
            user_handle: request.user_handle.clone(),
            user_name: request.user_name.clone(),
            user_display_name: request.user_display_name.clone(),
            algorithms: request.algorithms.clone(),
            exclude_credential_ids: request.exclude_credential_ids.clone(),
        },
    )?;
    let authenticator_data = build_registration_auth_data(
        &request.rp_id,
        &created.credential_id,
        &created.public_key.cose_key,
    )?;
    let attestation_object = build_none_attestation_object(&authenticator_data)?;
    Ok(MakeCredentialResponse {
        item_id: created.item_id,
        credential_id: created.credential_id,
        algorithm: created.algorithm,
        public_key: created.public_key,
        authenticator_data,
        attestation_object,
    })
}

/// Inputs to [`get_assertion`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetAssertionRequest {
    /// Canonical relying party identifier (already validated against origin).
    pub rp_id: String,
    /// SHA-256 hash of `clientDataJSON` (32 bytes).
    pub client_data_hash: [u8; 32],
    /// Optional `allowCredentials` filter; empty for discoverable credentials.
    pub allow_credential_ids: Vec<Vec<u8>>,
    /// Specific credential ID chosen by the user, or `None` to auto-select if
    /// exactly one credential matches.
    pub credential_id: Option<Vec<u8>>,
}

/// Output of [`get_assertion`]. Contains only public WebAuthn assertion fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetAssertionResponse {
    /// Vault item identifier of the credential used.
    pub item_id: ItemId,
    /// WebAuthn credential identifier.
    pub credential_id: Vec<u8>,
    /// Opaque user handle stored with the credential.
    pub user_handle: Vec<u8>,
    /// 37-byte `authenticatorData` (`UP|UV|BE|BS`, `signCount=0`).
    pub authenticator_data: [u8; ASSERTION_AUTH_DATA_LEN],
    /// Signature over `authenticator_data || client_data_hash` (ASN.1 DER for
    /// ES256, raw 64 bytes for EdDSA).
    pub signature: Vec<u8>,
}

/// Executes WebAuthn `getAssertion`: signs `authenticatorData || clientDataHash`
/// using the stored private key in `VK-K` without exposing the private key.
///
/// The caller must verify the user (UV) before invoking this function.
pub fn get_assertion(
    vault: &mut Vault,
    request: &GetAssertionRequest,
) -> Result<GetAssertionResponse, PasskeyError> {
    if request.rp_id.is_empty() || !request.rp_id.is_ascii() {
        return Err(PasskeyError::InvalidRpId(zp_origin::RpIdError::Malformed));
    }

    let chosen_id = match &request.credential_id {
        Some(id) => {
            if !request.allow_credential_ids.is_empty()
                && !request
                    .allow_credential_ids
                    .iter()
                    .any(|allowed| allowed == id)
            {
                return Err(PasskeyError::CredentialNotFound);
            }
            id.clone()
        }
        None => {
            let candidates =
                find_credentials(vault, &request.rp_id, &request.allow_credential_ids)?;
            match candidates.as_slice() {
                [] => return Err(PasskeyError::CredentialNotFound),
                [only] => only.credential_id.clone(),
                _ => return Err(PasskeyError::MultipleCredentials),
            }
        }
    };

    let (item_id, stored) = load_for_signing(vault, &request.rp_id, &chosen_id)?;
    let algorithm =
        Algorithm::from_cose(stored.cose_algorithm).ok_or(PasskeyError::UnsupportedAlgorithm)?;
    let authenticator_data = build_assertion_auth_data(&request.rp_id);
    let mut signed_data = [0u8; ASSERTION_AUTH_DATA_LEN + 32];
    signed_data[..ASSERTION_AUTH_DATA_LEN].copy_from_slice(&authenticator_data);
    signed_data[ASSERTION_AUTH_DATA_LEN..].copy_from_slice(&request.client_data_hash);

    let signature = sign_raw(algorithm, &stored.private_key, &signed_data)?;
    Ok(GetAssertionResponse {
        item_id,
        credential_id: stored.credential_id.clone(),
        user_handle: stored.user_handle.clone(),
        authenticator_data,
        signature,
    })
}

/// Verifies a WebAuthn assertion signature over `authenticator_data || client_data_hash`
/// and checks `rpIdHash`, flags (`UP` and `UV`), and `signCount == 0`.
pub fn verify_assertion(
    rp_id: &str,
    algorithm: Algorithm,
    spki_der: &[u8],
    client_data_hash: &[u8; 32],
    authenticator_data: &[u8],
    signature: &[u8],
) -> Result<(), PasskeyError> {
    if authenticator_data.len() < ASSERTION_AUTH_DATA_LEN {
        return Err(PasskeyError::InvalidSignature);
    }
    if authenticator_data[..32] != rp_id_hash(rp_id) {
        return Err(PasskeyError::InvalidSignature);
    }
    let flags = authenticator_data[32];
    if (flags & (FLAG_UP | FLAG_UV)) != (FLAG_UP | FLAG_UV) {
        return Err(PasskeyError::InvalidSignature);
    }
    let mut signed = Vec::with_capacity(authenticator_data.len() + 32);
    signed.extend_from_slice(authenticator_data);
    signed.extend_from_slice(client_data_hash);
    verify_raw(algorithm, spki_der, &signed, signature)
}

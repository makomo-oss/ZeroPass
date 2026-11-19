//! Passkey requests handled inside the passkey worker (`VK-K` domain,
//! ADR-0007, ADR-0010, `docs/spec/passkey.md`).

use zp_ipc::proto::{self, ErrorCode, response};
use zp_origin::{Origin, RpIdError};
use zp_passkey::{GetAssertionRequest, MakeCredentialRequest, PasskeyError, PasskeySummary};
use zp_vault::Vault;

use crate::convert::{bad_request, vault_error};
use crate::service::Reply;

/// Validates the page's origin, its top-level frame origin (rejecting
/// cross-site frames), and the requested RP ID (`docs/spec/passkey.md` §3).
/// Returns the canonical ASCII lower-case RP ID.
pub(crate) fn resolve_rp_id(
    origin: &str,
    top_origin: &str,
    rp_id: &str,
) -> Result<String, proto::Error> {
    let page = Origin::parse(origin).map_err(|error| bad_request(&error.to_string()))?;
    if !top_origin.is_empty() {
        let top = Origin::parse(top_origin).map_err(|error| bad_request(&error.to_string()))?;
        if !page.same_site(&top) {
            return Err(proto::Error::new(
                ErrorCode::Denied,
                "the page is a frame of another site",
            ));
        }
    }
    let requested = if rp_id.is_empty() { None } else { Some(rp_id) };
    page.validate_rp_id(requested).map_err(|error| match error {
        RpIdError::Malformed => bad_request(&error.to_string()),
        RpIdError::InsecureOrigin | RpIdError::NotAllowed => {
            proto::Error::new(ErrorCode::Denied, error.to_string())
        }
    })
}

/// Parses a 32-byte `clientDataHash`.
pub(crate) fn parse_client_data_hash(bytes: &[u8]) -> Result<[u8; 32], proto::Error> {
    bytes
        .try_into()
        .map_err(|_| bad_request("client_data_hash must be 32 bytes"))
}

fn passkey_error(error: PasskeyError) -> proto::Error {
    match error {
        PasskeyError::UnsupportedAlgorithm => {
            proto::Error::new(ErrorCode::UnsupportedAlgorithm, error.to_string())
        }
        PasskeyError::CredentialExcluded => {
            proto::Error::new(ErrorCode::CredentialExcluded, error.to_string())
        }
        PasskeyError::CredentialNotFound => {
            proto::Error::new(ErrorCode::ItemNotFound, error.to_string())
        }
        PasskeyError::MultipleCredentials | PasskeyError::InvalidUserHandle => {
            proto::Error::new(ErrorCode::InvalidInput, error.to_string())
        }
        PasskeyError::InvalidOrigin(message) => proto::Error::new(ErrorCode::Denied, message),
        PasskeyError::InvalidRpId(RpIdError::Malformed) => bad_request(&error.to_string()),
        PasskeyError::InvalidRpId(_) => proto::Error::new(ErrorCode::Denied, error.to_string()),
        PasskeyError::Vault(vault) => vault_error(vault),
        PasskeyError::MalformedKey
        | PasskeyError::InvalidSignature
        | PasskeyError::Cbor
        | PasskeyError::Rng => proto::Error::new(ErrorCode::Internal, error.to_string()),
    }
}

fn to_candidates(candidates: Vec<PasskeySummary>) -> response::Body {
    response::Body::PasskeyCandidates(proto::PasskeyCandidates {
        candidates: candidates
            .into_iter()
            .map(|c| proto::PasskeyCandidate {
                item_id: c.item_id.as_bytes().to_vec(),
                credential_id: c.credential_id,
                rp_id: c.rp_id,
                rp_name: c.rp_name,
                user_handle: c.user_handle,
                user_name: c.user_name,
                user_display_name: c.user_display_name,
                cose_algorithm: c.algorithm.cose_id(),
            })
            .collect(),
    })
}

/// Executes WebAuthn `makeCredential` inside the passkey worker. Never returns
/// private key material.
pub(crate) fn create(vault: &mut Vault, request: &proto::PasskeyCreate) -> Reply {
    let rp_id = resolve_rp_id(&request.origin, &request.top_origin, &request.rp_id)?;
    let client_data_hash = parse_client_data_hash(&request.client_data_hash)?;
    let created = zp_passkey::make_credential(
        vault,
        &MakeCredentialRequest {
            rp_id,
            rp_name: request.rp_name.clone(),
            user_handle: request.user_handle.clone(),
            user_name: request.user_name.clone(),
            user_display_name: request.user_display_name.clone(),
            algorithms: request.algorithms.clone(),
            exclude_credential_ids: request.exclude_credential_ids.clone(),
            client_data_hash,
        },
    )
    .map_err(passkey_error)?;
    Ok(response::Body::PasskeyCreated(proto::PasskeyCreated {
        item_id: created.item_id.as_bytes().to_vec(),
        credential_id: created.credential_id,
        public_key_spki: created.public_key.spki_der,
        public_key_cose: created.public_key.cose_key,
        cose_algorithm: created.algorithm.cose_id(),
        authenticator_data: created.authenticator_data,
        attestation_object: created.attestation_object,
    }))
}

/// Lists passkey candidates matching an origin and RP ID. Never returns
/// private key material.
pub(crate) fn list(vault: &mut Vault, request: &proto::PasskeyList) -> Reply {
    let rp_id = resolve_rp_id(&request.origin, &request.top_origin, &request.rp_id)?;
    let candidates = zp_passkey::find_credentials(vault, &rp_id, &request.allow_credential_ids)
        .map_err(passkey_error)?;
    Ok(to_candidates(candidates))
}

/// Executes WebAuthn `getAssertion` inside the passkey worker. If multiple
/// credentials match and `credential_id` was not chosen, returns
/// `PasskeyCandidates` so the caller can let the user pick one.
pub(crate) fn get_assertion(vault: &mut Vault, request: &proto::PasskeyGetAssertion) -> Reply {
    let rp_id = resolve_rp_id(&request.origin, &request.top_origin, &request.rp_id)?;
    let client_data_hash = parse_client_data_hash(&request.client_data_hash)?;
    let credential_id = if request.credential_id.is_empty() {
        None
    } else {
        Some(request.credential_id.clone())
    };
    let req = GetAssertionRequest {
        rp_id: rp_id.clone(),
        client_data_hash,
        allow_credential_ids: request.allow_credential_ids.clone(),
        credential_id,
    };
    match zp_passkey::get_assertion(vault, &req) {
        Ok(assertion) => Ok(response::Body::PasskeyAssertion(proto::PasskeyAssertion {
            item_id: assertion.item_id.as_bytes().to_vec(),
            credential_id: assertion.credential_id,
            user_handle: assertion.user_handle,
            authenticator_data: assertion.authenticator_data.to_vec(),
            signature: assertion.signature,
        })),
        Err(PasskeyError::MultipleCredentials) => {
            let candidates =
                zp_passkey::find_credentials(vault, &rp_id, &request.allow_credential_ids)
                    .map_err(passkey_error)?;
            Ok(to_candidates(candidates))
        }
        Err(error) => Err(passkey_error(error)),
    }
}

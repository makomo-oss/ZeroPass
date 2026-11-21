//! Passkeys (`docs/spec/passkey.md` §9).
//!
//! Made and used only in the process that holds the passkey domain: the
//! passkey worker (ADR-0007). The front checks a request before the user is
//! asked, and verifies the user anew for every one; the worker checks it
//! again, since it is the one that signs (G8).

use zp_ipc::proto::{self, ErrorCode, response};
use zp_passkey::{CreateRequest, GetOutcome, GetRequest, PasskeyError};
use zp_vault::Vault;

use crate::convert::vault_error;
use crate::service::Reply;

/// A passkey failure as the clients see it. Messages name the problem, never
/// the data.
pub(crate) fn error(error: PasskeyError) -> proto::Error {
    let message = error.to_string();
    let code = match error {
        PasskeyError::Vault(error) => return vault_error(error),
        PasskeyError::BadOrigin | PasskeyError::Invalid(_) => ErrorCode::BadRequest,
        PasskeyError::CrossSite | PasskeyError::BadRelyingParty => ErrorCode::Denied,
        PasskeyError::Excluded => ErrorCode::CredentialExcluded,
        PasskeyError::NoCredential => ErrorCode::ItemNotFound,
        PasskeyError::UnsupportedAlgorithm => ErrorCode::UnsupportedAlgorithm,
        PasskeyError::Random | PasskeyError::MalformedKey => ErrorCode::Internal,
    };
    proto::Error::new(code, message)
}

fn create_request(request: &proto::PasskeyCreate) -> CreateRequest<'_> {
    CreateRequest {
        origin: &request.origin,
        top_origin: &request.top_origin,
        rp_id: &request.rp_id,
        rp_name: &request.rp_name,
        user_handle: &request.user_handle,
        user_name: &request.user_name,
        user_display_name: &request.user_display_name,
        challenge: &request.challenge,
        algorithms: &request.algorithms,
        exclude: &request.exclude,
    }
}

fn get_request(request: &proto::PasskeyGet) -> GetRequest<'_> {
    GetRequest {
        origin: &request.origin,
        top_origin: &request.top_origin,
        rp_id: &request.rp_id,
        challenge: &request.challenge,
        allow: &request.allow,
        chosen: (!request.chosen.is_empty()).then_some(request.chosen.as_slice()),
    }
}

/// Fails if the request could never succeed, so that the user is not asked
/// for nothing: the page, its relying party, the algorithms, the sizes.
pub(crate) fn check_create(request: &proto::PasskeyCreate) -> Result<(), proto::Error> {
    zp_passkey::authenticator::check_create(&create_request(request))
        .map(drop)
        .map_err(error)
}

/// Like [`check_create`], for an assertion.
pub(crate) fn check_get(request: &proto::PasskeyGet) -> Result<(), proto::Error> {
    zp_passkey::authenticator::check_get(&get_request(request))
        .map(drop)
        .map_err(error)
}

/// Makes a passkey and keeps it in the vault.
pub(crate) fn create(vault: &mut Vault, request: &proto::PasskeyCreate) -> Reply {
    let made = zp_passkey::make_credential(vault, &create_request(request)).map_err(error)?;
    Ok(response::Body::PasskeyCreated(proto::PasskeyCreated {
        credential_id: made.credential_id,
        client_data_json: made.client_data_json,
        attestation_object: made.attestation_object,
        authenticator_data: made.authenticator_data,
        public_key: made.public_key,
        algorithm: made.algorithm.cose(),
    }))
}

/// Signs with a passkey of the page, or lists the ones to choose from.
pub(crate) fn get(vault: &mut Vault, request: &proto::PasskeyGet) -> Reply {
    match zp_passkey::get_assertion(vault, &get_request(request)).map_err(error)? {
        GetOutcome::Signed(assertion) => {
            Ok(response::Body::PasskeyAssertion(proto::PasskeyAssertion {
                credential_id: assertion.credential_id,
                client_data_json: assertion.client_data_json,
                authenticator_data: assertion.authenticator_data,
                signature: assertion.signature,
                user_handle: assertion.user_handle,
            }))
        }
        GetOutcome::Choose(choices) => Ok(response::Body::PasskeyChoices(proto::PasskeyChoices {
            choices: choices
                .into_iter()
                .map(|choice| proto::PasskeyChoice {
                    credential_id: choice.credential_id,
                    user_name: choice.user_name,
                    user_display_name: choice.user_display_name,
                })
                .collect(),
        })),
    }
}

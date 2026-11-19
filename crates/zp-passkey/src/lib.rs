//! OS-independent WebAuthn passkey authenticator engine for ZeroPass
//! (`docs/adr/0010-passkey-engine.md`, `docs/spec/passkey.md`).
//!
//! Private keys are generated and stored exclusively inside the vault's
//! `Passkey` (`VK-K`) domain and never leave the passkey worker process.

mod alg;
mod ceremony;
mod error;
mod store;

pub use alg::{
    Algorithm, COSE_ALG_EDDSA, COSE_ALG_ES256, GeneratedKeyPair, PublicKeyMaterial,
    generate_keypair, public_key_from_pkcs8, verify_raw,
};
pub use ceremony::{
    AAGUID, ASSERTION_AUTH_DATA_LEN, CeremonyType, FLAG_AT, FLAG_BE, FLAG_BS, FLAG_UP, FLAG_UV,
    FLAGS_GET_ASSERTION, FLAGS_MAKE_CREDENTIAL, GetAssertionRequest, GetAssertionResponse,
    MakeCredentialRequest, MakeCredentialResponse, SIGN_COUNT, base64url_encode,
    build_assertion_auth_data, build_client_data_json, build_none_attestation_object,
    build_registration_auth_data, get_assertion, make_credential, rp_id_hash, verify_assertion,
};
pub use error::PasskeyError;
pub use store::{
    CREDENTIAL_ID_LEN, CreateParams, CreatedCredential, MAX_USER_HANDLE_LEN, PasskeySummary,
    create_credential, find_credentials,
};

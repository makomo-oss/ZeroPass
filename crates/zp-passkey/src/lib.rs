//! OS-independent WebAuthn passkey authenticator engine for ZeroPass
//! (`docs/adr/0010-passkey-engine.md`, `docs/spec/passkey.md`).
//!
//! Private keys are generated and stored exclusively inside the vault's
//! `Passkey` (`VK-K`) domain and never leave the passkey worker process.

mod alg;
mod error;
mod store;

pub use alg::{
    Algorithm, COSE_ALG_EDDSA, COSE_ALG_ES256, GeneratedKeyPair, PublicKeyMaterial,
    generate_keypair, public_key_from_pkcs8, verify_raw,
};
pub use error::PasskeyError;
pub use store::{
    CREDENTIAL_ID_LEN, CreateParams, CreatedCredential, MAX_USER_HANDLE_LEN, PasskeySummary,
    create_credential, find_credentials,
};

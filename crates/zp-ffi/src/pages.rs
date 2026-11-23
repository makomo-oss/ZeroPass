//! Filling and passkeys for other apps (`docs/spec/android.md` §6): what the
//! autofill service and the Credential Manager provider ask the vault
//! process, as the browser extension's bridge does on the desktop
//! (`docs/spec/extension.md` §4, `docs/spec/passkey.md` §9).
//!
//! A *page* is the origin of a web page in a browser the app trusts, or
//! `androidapp://<package>` for an app. The vault process decides which logins
//! belong to it and hands out a password only for one of them.

use zp_ipc::proto::{self, request, response};

use crate::client::VaultClient;
use crate::error::{Problem, ZpError};
use crate::{hex, parse_hex};

/// A login that belongs to a page: no secret.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PageLogin {
    /// The item's identifier (hexadecimal).
    pub id: String,
    /// Its title.
    pub title: String,
    /// Its user name.
    pub username: String,
    /// Whether it was saved for exactly this page (not only its site).
    pub exact: bool,
}

/// The user name and password of one login.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PageCredential {
    /// The user name.
    pub username: String,
    /// The password.
    pub password: String,
}

/// Whether what was typed into a page is already in the vault.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PageComparison {
    /// The login of the page with that user name, if any (hexadecimal).
    pub id: Option<String>,
    /// Whether that login (or one without user name) has that password.
    pub same: bool,
}

/// A passkey to make for a site (`navigator.credentials.create`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PasskeyCreation {
    /// The page's origin, as the browser vouches for it.
    pub origin: String,
    /// `rp.id`; empty: the page's host.
    pub rp_id: String,
    /// `rp.name`.
    pub rp_name: String,
    /// `user.id`.
    pub user_handle: Vec<u8>,
    /// `user.name`.
    pub user_name: String,
    /// `user.displayName`.
    pub user_display_name: String,
    /// `challenge`.
    pub challenge: Vec<u8>,
    /// The COSE algorithms of `pubKeyCredParams`, preferred first.
    pub algorithms: Vec<i32>,
    /// The identifiers of `excludeCredentials`.
    pub exclude: Vec<Vec<u8>>,
    /// The SHA-256 of the client data the browser made, if it did.
    pub client_data_hash: Option<Vec<u8>>,
}

/// A new passkey, as the site receives it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PasskeyMade {
    /// The credential identifier.
    pub credential_id: Vec<u8>,
    /// The client data JSON; empty when the browser made it.
    pub client_data_json: Vec<u8>,
    /// The attestation object ("none").
    pub attestation_object: Vec<u8>,
    /// The authenticator data.
    pub authenticator_data: Vec<u8>,
    /// The public key as SubjectPublicKeyInfo.
    pub public_key: Vec<u8>,
    /// Its COSE algorithm.
    pub algorithm: i32,
}

/// A request to sign in with a passkey (`navigator.credentials.get`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PasskeyRequest {
    /// The page's origin, as the browser vouches for it.
    pub origin: String,
    /// `rpId`; empty: the page's host.
    pub rp_id: String,
    /// `challenge`.
    pub challenge: Vec<u8>,
    /// The identifiers of `allowCredentials` (empty: any of the site's).
    pub allow: Vec<Vec<u8>>,
    /// The SHA-256 of the client data the browser made, if it did.
    pub client_data_hash: Option<Vec<u8>>,
}

/// A passkey to pick: nothing secret.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PasskeyChoice {
    /// The credential identifier.
    pub credential_id: Vec<u8>,
    /// The account name.
    pub user_name: String,
    /// The display name.
    pub user_display_name: String,
}

/// An assertion, as the site receives it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PasskeySignature {
    /// The credential that signed.
    pub credential_id: Vec<u8>,
    /// The client data JSON; empty when the browser made it.
    pub client_data_json: Vec<u8>,
    /// The authenticator data.
    pub authenticator_data: Vec<u8>,
    /// The signature.
    pub signature: Vec<u8>,
    /// The user handle.
    pub user_handle: Vec<u8>,
}

fn item(id: &str) -> Result<Vec<u8>, ZpError> {
    parse_hex::<16>(id)
        .map(|bytes| bytes.to_vec())
        .ok_or_else(|| ZpError::new(Problem::InvalidInput, "malformed item identifier"))
}

fn unexpected() -> ZpError {
    ZpError::failed("the vault process gave an unexpected answer")
}

impl PasskeyRequest {
    fn to_proto(&self, chosen: Vec<u8>, list_only: bool) -> proto::PasskeyGet {
        proto::PasskeyGet {
            origin: self.origin.clone(),
            top_origin: String::new(),
            rp_id: self.rp_id.clone(),
            challenge: self.challenge.clone(),
            allow: self.allow.clone(),
            chosen,
            client_data_hash: self.client_data_hash.clone().unwrap_or_default(),
            list_only,
        }
    }
}

#[uniffi::export]
impl VaultClient {
    /// The logins that belong to `page`, best first. The password domain must
    /// be unlocked.
    pub fn page_logins(&self, page: String) -> Result<Vec<PageLogin>, ZpError> {
        let response::Body::BridgeLogins(logins) =
            self.call(request::Body::BridgeFind(proto::BridgeFind {
                origin: page,
                top_origin: String::new(),
            }))?
        else {
            return Err(unexpected());
        };
        Ok(logins
            .logins
            .into_iter()
            .map(|login| PageLogin {
                id: hex(&login.item_id),
                title: login.title,
                username: login.username,
                exact: login.exact,
            })
            .collect())
    }

    /// The user name and password of the login `id`, if it belongs to `page`.
    pub fn page_credential(&self, page: String, id: String) -> Result<PageCredential, ZpError> {
        match self.call(request::Body::BridgeFill(proto::BridgeFill {
            origin: page,
            item_id: item(&id)?,
            top_origin: String::new(),
        }))? {
            response::Body::BridgeCredential(credential) => Ok(PageCredential {
                username: credential.username.clone(),
                password: credential.password.clone(),
            }),
            _ => Err(unexpected()),
        }
    }

    /// Whether `username` and `password`, typed into `page`, are in the vault.
    pub fn compare_page_login(
        &self,
        page: String,
        username: String,
        password: String,
    ) -> Result<PageComparison, ZpError> {
        match self.call(request::Body::BridgeCompare(proto::BridgeCompare {
            origin: page,
            top_origin: String::new(),
            username,
            password,
        }))? {
            response::Body::BridgeComparison(comparison) => Ok(PageComparison {
                id: (!comparison.item_id.is_empty()).then(|| hex(&comparison.item_id)),
                same: comparison.same,
            }),
            _ => Err(unexpected()),
        }
    }

    /// Saves a new login for `page`, with the page as its address.
    pub fn save_page_login(
        &self,
        page: String,
        title: String,
        username: String,
        password: String,
    ) -> Result<String, ZpError> {
        match self.call(request::Body::BridgeSave(proto::BridgeSave {
            origin: page,
            top_origin: String::new(),
            title,
            username,
            password,
        }))? {
            response::Body::ItemAdded(added) => Ok(hex(&added.item_id)),
            _ => Err(unexpected()),
        }
    }

    /// Replaces the password of the login `id` of `page`.
    pub fn update_page_login(
        &self,
        page: String,
        id: String,
        password: String,
    ) -> Result<(), ZpError> {
        self.call(request::Body::BridgeUpdate(proto::BridgeUpdate {
            origin: page,
            top_origin: String::new(),
            item_id: item(&id)?,
            password,
        }))
        .map(drop)
    }

    /// Makes a passkey for the site. The key store verifies the user.
    pub fn create_passkey(&self, creation: PasskeyCreation) -> Result<PasskeyMade, ZpError> {
        let create = proto::PasskeyCreate {
            origin: creation.origin,
            top_origin: String::new(),
            rp_id: creation.rp_id,
            rp_name: creation.rp_name,
            user_handle: creation.user_handle,
            user_name: creation.user_name,
            user_display_name: creation.user_display_name,
            challenge: creation.challenge,
            algorithms: creation.algorithms,
            exclude: creation.exclude,
            client_data_hash: creation.client_data_hash.unwrap_or_default(),
        };
        match self.call(request::Body::PasskeyCreate(create))? {
            response::Body::PasskeyCreated(made) => Ok(PasskeyMade {
                credential_id: made.credential_id,
                client_data_json: made.client_data_json,
                attestation_object: made.attestation_object,
                authenticator_data: made.authenticator_data,
                public_key: made.public_key,
                algorithm: made.algorithm,
            }),
            _ => Err(unexpected()),
        }
    }

    /// The site's passkeys to pick from, without signing. The key store
    /// verifies the user; the pick is then signed without asking again
    /// ([`Self::sign_with_passkey`] with the same request, for two minutes).
    pub fn passkey_choices(&self, request: PasskeyRequest) -> Result<Vec<PasskeyChoice>, ZpError> {
        match self.call(request::Body::PasskeyGet(
            request.to_proto(Vec::new(), true),
        ))? {
            response::Body::PasskeyChoices(choices) => Ok(choices
                .choices
                .into_iter()
                .map(|choice| PasskeyChoice {
                    credential_id: choice.credential_id,
                    user_name: choice.user_name,
                    user_display_name: choice.user_display_name,
                })
                .collect()),
            _ => Err(unexpected()),
        }
    }

    /// Signs with the passkey `credential_id` of the site.
    pub fn sign_with_passkey(
        &self,
        request: PasskeyRequest,
        credential_id: Vec<u8>,
    ) -> Result<PasskeySignature, ZpError> {
        match self.call(request::Body::PasskeyGet(
            request.to_proto(credential_id, false),
        ))? {
            response::Body::PasskeyAssertion(assertion) => Ok(PasskeySignature {
                credential_id: assertion.credential_id,
                client_data_json: assertion.client_data_json,
                authenticator_data: assertion.authenticator_data,
                signature: assertion.signature,
                user_handle: assertion.user_handle,
            }),
            _ => Err(unexpected()),
        }
    }
}

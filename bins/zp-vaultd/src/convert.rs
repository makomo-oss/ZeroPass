//! Conversions between the vault's types and the messages of the IPC.

use zp_crypto::{CryptoError, DeviceId, DomainId, HardwareKeyError, ItemId};
use zp_ipc::proto::{self, ErrorCode, item};
use zp_vault::model::{Content, Login, SecureNote, TotpEntry};
use zp_vault::{VaultError, is_user_cancelled, totp};

/// The IPC name of a key domain.
pub(crate) fn domain_to_proto(domain: DomainId) -> proto::Domain {
    match domain {
        DomainId::Password => proto::Domain::Password,
        DomainId::Totp => proto::Domain::Totp,
        DomainId::Passkey => proto::Domain::Passkey,
    }
}

/// The key domain named in a request.
pub(crate) fn domain_from_proto(domain: i32) -> Result<DomainId, proto::Error> {
    match proto::Domain::try_from(domain) {
        Ok(proto::Domain::Password) => Ok(DomainId::Password),
        Ok(proto::Domain::Totp) => Ok(DomainId::Totp),
        Ok(proto::Domain::Passkey) => Ok(DomainId::Passkey),
        Ok(proto::Domain::Unspecified) | Err(_) => Err(bad_request("the request names no domain")),
    }
}

/// Lower-case name of a domain, for messages.
pub(crate) fn domain_name(domain: DomainId) -> &'static str {
    match domain {
        DomainId::Password => "password",
        DomainId::Totp => "totp",
        DomainId::Passkey => "passkey",
    }
}

pub(crate) fn bad_request(message: &str) -> proto::Error {
    proto::Error::new(ErrorCode::BadRequest, message)
}

pub(crate) fn locked(domain: DomainId) -> proto::Error {
    proto::Error::about(
        ErrorCode::Locked,
        domain_to_proto(domain),
        format!("the {} domain is locked", domain_name(domain)),
    )
}

pub(crate) fn item_id(bytes: &[u8]) -> Result<ItemId, proto::Error> {
    ItemId::from_slice(bytes).ok_or_else(|| bad_request("an item identifier is 16 bytes"))
}

pub(crate) fn device_id(bytes: &[u8]) -> Result<DeviceId, proto::Error> {
    <[u8; DeviceId::LEN]>::try_from(bytes)
        .map(DeviceId::from_bytes)
        .map_err(|_| bad_request("the device identifier has the wrong length"))
}

/// What a client is told when a vault operation fails. Messages name the
/// problem, never the data.
pub(crate) fn vault_error(error: VaultError) -> proto::Error {
    if is_user_cancelled(&error) {
        return proto::Error::new(ErrorCode::UserCancelled, error.to_string());
    }
    let message = error.to_string();
    let code = match &error {
        VaultError::AlreadyExists => ErrorCode::VaultExists,
        VaultError::NotFound => ErrorCode::NoVault,
        VaultError::Locked(domain) => return locked(*domain),
        VaultError::DomainUnavailable(domain) => {
            return proto::Error::about(
                ErrorCode::DomainUnavailable,
                domain_to_proto(*domain),
                format!(
                    "this vault has no {} domain (it was created without a hardware key store)",
                    domain_name(*domain)
                ),
            );
        }
        VaultError::WrongPassword => ErrorCode::WrongPassword,
        VaultError::WeakPassword => ErrorCode::WeakPassword,
        VaultError::NoRecoveryKit => ErrorCode::NoRecoveryKit,
        VaultError::WrongRecoveryKey => ErrorCode::WrongRecoveryKey,
        VaultError::ItemNotFound => ErrorCode::ItemNotFound,
        VaultError::WrongItemKind | VaultError::DomainMismatch => ErrorCode::WrongItemKind,
        VaultError::CannotRevokeSelf => ErrorCode::DeviceNotFound,
        VaultError::Totp(_) => ErrorCode::InvalidInput,
        VaultError::Crypto(CryptoError::InvalidRecoveryKey) => ErrorCode::InvalidInput,
        VaultError::Crypto(CryptoError::HardwareKey(HardwareKeyError::Unavailable(_))) => {
            ErrorCode::HardwareUnavailable
        }
        _ => ErrorCode::Internal,
    };
    proto::Error::new(code, message)
}

/// The summary of an item for lists: no secrets.
pub(crate) fn summary(id: ItemId, content: &Content) -> proto::ItemSummary {
    let (kind, username, urls) = match content {
        Content::Login(login) => (
            proto::ItemKind::Login,
            login.username.clone(),
            login.urls.clone(),
        ),
        Content::SecureNote(_) => (proto::ItemKind::Note, String::new(), Vec::new()),
        Content::Totp(entry) => (proto::ItemKind::Totp, entry.account.clone(), Vec::new()),
        Content::Passkey(passkey) => (
            proto::ItemKind::Passkey,
            passkey.user_name.clone(),
            Vec::new(),
        ),
    };
    proto::ItemSummary {
        item_id: id.as_bytes().to_vec(),
        kind: kind as i32,
        title: content.title().to_owned(),
        username,
        urls,
    }
}

/// What a client may see of an item (`docs/spec/ipc.md` §6): everything of a
/// login or a note, but neither the seed of a TOTP entry nor the private key of
/// a passkey.
pub(crate) fn item(id: ItemId, content: &Content) -> proto::Item {
    let content = match content {
        Content::Login(login) => item::Content::Login(proto::Login {
            title: login.title.clone(),
            username: login.username.clone(),
            password: login.password.clone(),
            urls: login.urls.clone(),
            notes: login.notes.clone(),
        }),
        Content::SecureNote(note) => item::Content::Note(proto::Note {
            title: note.title.clone(),
            body: note.body.clone(),
        }),
        Content::Totp(entry) => item::Content::Totp(proto::TotpInfo {
            issuer: entry.issuer.clone(),
            account: entry.account.clone(),
            digits: entry.digits,
            period: entry.period,
            login_id: entry.login().map(|login| login.as_bytes().to_vec()),
        }),
        Content::Passkey(passkey) => item::Content::Passkey(proto::PasskeyInfo {
            rp_id: passkey.rp_id.clone(),
            user_name: passkey.user_name.clone(),
        }),
    };
    proto::Item {
        item_id: id.as_bytes().to_vec(),
        content: Some(content),
    }
}

/// An item handed in by a client, as the vault's own type.
pub(crate) enum NewItem {
    Login(Login),
    Note(SecureNote),
    Totp(TotpEntry),
}

impl NewItem {
    /// The domain the item is stored in.
    pub(crate) fn domain(&self) -> DomainId {
        match self {
            NewItem::Login(_) | NewItem::Note(_) => DomainId::Password,
            NewItem::Totp(_) => DomainId::Totp,
        }
    }
}

pub(crate) fn new_item(item: Option<proto::NewItem>) -> Result<NewItem, proto::Error> {
    use proto::new_item::Content as New;
    match item.and_then(|item| item.content) {
        Some(New::Login(login)) => {
            let mut item = Login::new(
                login.title.as_str(),
                login.username.as_str(),
                login.password.as_str(),
            );
            item.urls = login.urls.clone();
            item.notes = login.notes.clone();
            Ok(NewItem::Login(item))
        }
        Some(New::Note(note)) => Ok(NewItem::Note(SecureNote::new(
            note.title.as_str(),
            note.body.as_str(),
        ))),
        Some(New::Totp(new)) => {
            let mut entry = totp::parse_otpauth_uri(&new.otpauth_uri)
                .map_err(|error| proto::Error::new(ErrorCode::InvalidInput, error.to_string()))?;
            if let Some(login) = &new.login_id {
                entry = entry.for_login(item_id(login)?);
            }
            Ok(NewItem::Totp(entry))
        }
        None => Err(bad_request("the request carries no item")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zp_vault::model::{Item as _, PasskeyCredential};

    const SEED: &[u8] = b"12345678901234567890";

    #[test]
    fn a_totp_seed_and_a_passkey_private_key_never_reach_a_reply() {
        let id = ItemId::from_bytes([1; 16]);
        let entry = TotpEntry::new("Example", "alice", SEED.to_vec()).into_content();
        let passkey = PasskeyCredential {
            rp_id: "example.com".into(),
            rp_name: "Example".into(),
            user_handle: b"user-handle-bytes".to_vec(),
            user_name: "alice".into(),
            user_display_name: "Alice".into(),
            credential_id: b"credential-id-bytes".to_vec(),
            private_key: b"private-key-bytes-private-key-bytes".to_vec(),
            cose_algorithm: -7,
        }
        .into_content();

        for content in [&entry, &passkey] {
            let full = format!("{:?}", item(id, content));
            let brief = format!("{:?}", summary(id, content));
            for secret in [
                SEED,
                b"private-key-bytes",
                b"credential-id-bytes",
                b"user-handle-bytes",
            ] {
                assert!(!contains(&full, secret), "{full}");
                assert!(!contains(&brief, secret), "{brief}");
            }
        }
        // What may be shown is there.
        match item(id, &entry).content {
            Some(item::Content::Totp(info)) => {
                assert_eq!(info.issuer, "Example");
                assert_eq!(info.account, "alice");
                assert_eq!((info.digits, info.period), (6, 30));
            }
            _ => panic!("not a TOTP entry"),
        }
    }

    /// Looks for a byte string in the debug rendering of a message, in the
    /// forms a `Vec<u8>` or a `String` field would take.
    fn contains(rendered: &str, secret: &[u8]) -> bool {
        let as_text = String::from_utf8_lossy(secret);
        let as_list = format!("{secret:?}");
        rendered.contains(as_text.as_ref()) || rendered.contains(&as_list)
    }

    #[test]
    fn a_summary_of_a_login_has_no_password() {
        let mut login = Login::new("Example", "alice", "hunter2-hunter2");
        login.notes = "the answer is 42".into();
        let content = login.into_content();
        let brief = format!("{:?}", summary(ItemId::from_bytes([2; 16]), &content));
        assert!(brief.contains("alice"));
        assert!(!brief.contains("hunter2"), "{brief}");
        assert!(!brief.contains("answer"), "{brief}");
    }

    #[test]
    fn errors_keep_their_meaning() {
        let error = vault_error(VaultError::Locked(DomainId::Totp));
        assert_eq!(error.code, ErrorCode::Locked as i32);
        assert_eq!(error.domain, Some(proto::Domain::Totp as i32));
        let error = vault_error(VaultError::WrongPassword);
        assert_eq!(error.code, ErrorCode::WrongPassword as i32);
        let cancelled =
            VaultError::Crypto(CryptoError::HardwareKey(HardwareKeyError::UserCancelled));
        assert_eq!(vault_error(cancelled).code, ErrorCode::UserCancelled as i32);
    }

    #[test]
    fn identifiers_of_the_wrong_length_are_bad_requests() {
        assert!(item_id(&[0; 15]).is_err());
        assert!(item_id(&[0; 16]).is_ok());
        assert!(device_id(&[]).is_err());
        assert!(domain_from_proto(0).is_err());
        assert!(domain_from_proto(99).is_err());
        assert_eq!(domain_from_proto(2).ok(), Some(DomainId::Totp));
    }
}

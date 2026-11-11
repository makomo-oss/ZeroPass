//! The item data model.
//!
//! Items are serialised with Protocol Buffers and stored only inside an AEAD
//! envelope (`docs/spec/crypto.md` §9): the item kind and every field, including
//! titles and URLs, are ciphertext on disk. The message types in this module are
//! the source of truth for the wire format; field tags must never be reused.
//!
//! Each kind belongs to exactly one key domain:
//!
//! | Kind | Domain |
//! |---|---|
//! | [`Login`], [`SecureNote`] | [`Password`] |
//! | [`TotpEntry`] | [`Totp`] |
//! | [`PasskeyCredential`] | [`Passkey`] |
//!
//! All item types wipe their contents on drop and print nothing in `Debug`.

use core::fmt;

use prost::Message;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use zp_crypto::{Domain, DomainId, ItemId, Passkey, Password, Totp};

use crate::VaultError;

mod sealed {
    pub trait Sealed {}
}

/// The kind of an item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ItemKind {
    /// A website or application login.
    Login,
    /// A free-form secure note.
    SecureNote,
    /// A TOTP (two-factor) seed.
    Totp,
    /// A WebAuthn passkey credential.
    Passkey,
}

impl ItemKind {
    /// The key domain items of this kind are stored in.
    pub const fn domain(self) -> DomainId {
        match self {
            ItemKind::Login | ItemKind::SecureNote => DomainId::Password,
            ItemKind::Totp => DomainId::Totp,
            ItemKind::Passkey => DomainId::Passkey,
        }
    }
}

/// A website or application login.
#[derive(Clone, PartialEq, Message, Zeroize, ZeroizeOnDrop)]
#[prost(skip_debug)]
pub struct Login {
    /// Display name.
    #[prost(string, tag = "1")]
    pub title: String,
    /// User name or e-mail address.
    #[prost(string, tag = "2")]
    pub username: String,
    /// The password.
    #[prost(string, tag = "3")]
    pub password: String,
    /// URLs this login applies to.
    #[prost(string, repeated, tag = "4")]
    pub urls: Vec<String>,
    /// Free-form notes.
    #[prost(string, tag = "5")]
    pub notes: String,
}

impl Login {
    /// Creates a login with the given title, user name and password.
    pub fn new(
        title: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            title: title.into(),
            username: username.into(),
            password: password.into(),
            urls: Vec::new(),
            notes: String::new(),
        }
    }

    /// Adds a URL this login applies to.
    #[must_use]
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.urls.push(url.into());
        self
    }
}

/// A free-form secure note.
#[derive(Clone, PartialEq, Message, Zeroize, ZeroizeOnDrop)]
#[prost(skip_debug)]
pub struct SecureNote {
    /// Display name.
    #[prost(string, tag = "1")]
    pub title: String,
    /// The note text.
    #[prost(string, tag = "2")]
    pub body: String,
}

impl SecureNote {
    /// Creates a note.
    pub fn new(title: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            body: body.into(),
        }
    }
}

/// Hash function of a TOTP entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum TotpAlgorithm {
    /// HMAC-SHA-1 (the default of virtually every service).
    Sha1 = 0,
    /// HMAC-SHA-256.
    Sha256 = 1,
    /// HMAC-SHA-512.
    Sha512 = 2,
}

/// A TOTP seed and its parameters (RFC 6238).
#[derive(Clone, PartialEq, Message, Zeroize, ZeroizeOnDrop)]
#[prost(skip_debug)]
pub struct TotpEntry {
    /// The service that issued the secret.
    #[prost(string, tag = "1")]
    pub issuer: String,
    /// The account the secret belongs to.
    #[prost(string, tag = "2")]
    pub account: String,
    /// The shared secret (raw bytes, not Base32).
    #[prost(bytes = "vec", tag = "3")]
    pub secret: Vec<u8>,
    /// Hash function; see [`TotpAlgorithm`].
    #[prost(enumeration = "TotpAlgorithm", tag = "4")]
    pub algorithm: i32,
    /// Number of digits in a code (6 to 8).
    #[prost(uint32, tag = "5")]
    pub digits: u32,
    /// Time step in seconds.
    #[prost(uint32, tag = "6")]
    pub period: u32,
    /// The [`Login`] this entry belongs to (16 bytes), or empty.
    #[prost(bytes = "vec", tag = "7")]
    pub login_item_id: Vec<u8>,
}

impl TotpEntry {
    /// Default number of digits.
    pub const DEFAULT_DIGITS: u32 = 6;
    /// Default time step in seconds.
    pub const DEFAULT_PERIOD: u32 = 30;

    /// Creates an entry with the common parameters: SHA-1, 6 digits, 30 seconds.
    pub fn new(issuer: impl Into<String>, account: impl Into<String>, secret: Vec<u8>) -> Self {
        Self {
            issuer: issuer.into(),
            account: account.into(),
            secret,
            algorithm: TotpAlgorithm::Sha1 as i32,
            digits: Self::DEFAULT_DIGITS,
            period: Self::DEFAULT_PERIOD,
            login_item_id: Vec::new(),
        }
    }

    /// Links this entry to a login.
    #[must_use]
    pub fn for_login(mut self, login: ItemId) -> Self {
        self.login_item_id = login.as_bytes().to_vec();
        self
    }

    /// The linked login, if any.
    pub fn login(&self) -> Option<ItemId> {
        ItemId::from_slice(&self.login_item_id)
    }
}

/// A WebAuthn passkey credential. The signing engine arrives with Phase 5; the
/// stored shape is fixed here so the passkey domain is exercised from the start.
#[derive(Clone, PartialEq, Message, Zeroize, ZeroizeOnDrop)]
#[prost(skip_debug)]
pub struct PasskeyCredential {
    /// Relying party identifier (for example `example.com`).
    #[prost(string, tag = "1")]
    pub rp_id: String,
    /// Relying party display name.
    #[prost(string, tag = "2")]
    pub rp_name: String,
    /// The user handle assigned by the relying party.
    #[prost(bytes = "vec", tag = "3")]
    pub user_handle: Vec<u8>,
    /// The user's account name.
    #[prost(string, tag = "4")]
    pub user_name: String,
    /// The user's display name.
    #[prost(string, tag = "5")]
    pub user_display_name: String,
    /// The credential identifier.
    #[prost(bytes = "vec", tag = "6")]
    pub credential_id: Vec<u8>,
    /// The private key, PKCS #8 DER.
    #[prost(bytes = "vec", tag = "7")]
    pub private_key: Vec<u8>,
    /// COSE algorithm identifier (`-7` = ES256, `-8` = EdDSA).
    #[prost(sint32, tag = "8")]
    pub cose_algorithm: i32,
}

/// The content of an item: exactly one of the item kinds.
#[derive(Clone, PartialEq, prost::Oneof)]
#[prost(skip_debug)]
pub enum Content {
    /// A login.
    #[prost(message, tag = "1")]
    Login(Login),
    /// A secure note.
    #[prost(message, tag = "2")]
    SecureNote(SecureNote),
    /// A TOTP entry.
    #[prost(message, tag = "3")]
    Totp(TotpEntry),
    /// A passkey credential.
    #[prost(message, tag = "4")]
    Passkey(PasskeyCredential),
}

impl Content {
    /// The kind of this content.
    pub const fn kind(&self) -> ItemKind {
        match self {
            Content::Login(_) => ItemKind::Login,
            Content::SecureNote(_) => ItemKind::SecureNote,
            Content::Totp(_) => ItemKind::Totp,
            Content::Passkey(_) => ItemKind::Passkey,
        }
    }

    /// A human-readable name for lists.
    pub fn title(&self) -> &str {
        match self {
            Content::Login(login) => &login.title,
            Content::SecureNote(note) => &note.title,
            Content::Totp(totp) => &totp.issuer,
            Content::Passkey(passkey) => &passkey.rp_id,
        }
    }

    /// Whether the item matches a search query: a case-insensitive substring
    /// match against its non-secret, human-facing fields (titles, user names,
    /// URLs, issuers). Passwords, note bodies and seeds are never searched. An
    /// empty query matches everything.
    pub fn matches(&self, query: &str) -> bool {
        let query = query.trim().to_lowercase();
        let hit = |field: &str| field.to_lowercase().contains(&query);
        match self {
            Content::Login(login) => {
                hit(&login.title) || hit(&login.username) || login.urls.iter().any(|url| hit(url))
            }
            Content::SecureNote(note) => hit(&note.title),
            Content::Totp(totp) => hit(&totp.issuer) || hit(&totp.account),
            Content::Passkey(passkey) => {
                hit(&passkey.rp_id) || hit(&passkey.rp_name) || hit(&passkey.user_name)
            }
        }
    }

    /// Serialises the content for encryption.
    pub fn to_plaintext(&self) -> Zeroizing<Vec<u8>> {
        let record = ItemRecord {
            content: Some(self.clone()),
        };
        Zeroizing::new(record.encode_to_vec())
    }

    /// Parses decrypted content and checks that its kind belongs to `domain`, the
    /// domain of the row it was stored in.
    pub fn from_plaintext(plaintext: &[u8], domain: DomainId) -> Result<Self, VaultError> {
        let mut record = ItemRecord::decode(plaintext).map_err(|_| VaultError::MalformedItem)?;
        let content = record.content.take().ok_or(VaultError::MalformedItem)?;
        if content.kind().domain() != domain {
            return Err(VaultError::MalformedItem);
        }
        Ok(content)
    }
}

/// The top-level message stored inside an item envelope.
#[derive(Clone, PartialEq, Message)]
#[prost(skip_debug)]
struct ItemRecord {
    #[prost(oneof = "Content", tags = "1, 2, 3, 4")]
    content: Option<Content>,
}

/// An item kind, tied at compile time to the key domain it is stored in.
pub trait Item: sealed::Sealed + Sized {
    /// The key domain of this kind.
    type Domain: Domain;
    /// The runtime kind.
    const KIND: ItemKind;

    /// Wraps the item as [`Content`].
    fn into_content(self) -> Content;
    /// Extracts the item if `content` is of this kind.
    fn from_content(content: Content) -> Option<Self>;
}

macro_rules! item {
    ($ty:ident, $variant:ident, $domain:ty) => {
        impl sealed::Sealed for $ty {}

        impl Item for $ty {
            type Domain = $domain;
            const KIND: ItemKind = ItemKind::$variant;

            fn into_content(self) -> Content {
                Content::$variant(self)
            }

            fn from_content(content: Content) -> Option<Self> {
                match content {
                    Content::$variant(item) => Some(item),
                    _ => None,
                }
            }
        }

        impl fmt::Debug for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($ty), "(<redacted>)"))
            }
        }
    };
}

item!(Login, Login, Password);
item!(SecureNote, SecureNote, Password);
item!(TotpEntry, Totp, Totp);
item!(PasskeyCredential, Passkey, Passkey);

impl fmt::Debug for Content {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Content::{:?}(<redacted>)", self.kind())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login() -> Login {
        let mut login = Login::new("Example", "alice@example.com", "hunter2-hunter2")
            .with_url("https://example.com/login");
        login.notes = "security question: none".into();
        login
    }

    fn passkey() -> PasskeyCredential {
        PasskeyCredential {
            rp_id: "example.com".into(),
            rp_name: String::new(),
            user_handle: vec![1, 2, 3],
            user_name: String::new(),
            user_display_name: String::new(),
            credential_id: vec![9; 16],
            private_key: vec![7; 48],
            cose_algorithm: -7,
        }
    }

    #[test]
    fn every_kind_round_trips() {
        let totp =
            TotpEntry::new("Example", "alice", vec![1; 20]).for_login(ItemId::from_bytes([5; 16]));
        let contents = [
            login().into_content(),
            SecureNote::new("Wi-Fi", "passphrase: correct horse").into_content(),
            totp.into_content(),
            passkey().into_content(),
        ];
        for content in contents {
            let bytes = content.to_plaintext();
            let back = Content::from_plaintext(&bytes, content.kind().domain()).unwrap();
            assert_eq!(back, content);
        }
    }

    #[test]
    fn typed_extraction_matches_the_kind() {
        let content = login().into_content();
        assert_eq!(content.kind(), ItemKind::Login);
        assert_eq!(content.title(), "Example");
        assert!(SecureNote::from_content(content.clone()).is_none());
        assert_eq!(Login::from_content(content).unwrap(), login());
    }

    #[test]
    fn kinds_map_to_their_domains() {
        assert_eq!(ItemKind::Login.domain(), DomainId::Password);
        assert_eq!(ItemKind::SecureNote.domain(), DomainId::Password);
        assert_eq!(ItemKind::Totp.domain(), DomainId::Totp);
        assert_eq!(ItemKind::Passkey.domain(), DomainId::Passkey);
        assert_eq!(
            <TotpEntry as Item>::Domain::ID,
            <TotpEntry as Item>::KIND.domain()
        );
        assert_eq!(<Login as Item>::Domain::ID, <Login as Item>::KIND.domain());
        assert_eq!(
            <PasskeyCredential as Item>::Domain::ID,
            <PasskeyCredential as Item>::KIND.domain()
        );
    }

    #[test]
    fn content_stored_in_the_wrong_domain_is_rejected() {
        let bytes = TotpEntry::new("Example", "alice", vec![1; 20])
            .into_content()
            .to_plaintext();
        assert!(matches!(
            Content::from_plaintext(&bytes, DomainId::Password),
            Err(VaultError::MalformedItem)
        ));
        assert!(Content::from_plaintext(&bytes, DomainId::Totp).is_ok());
    }

    #[test]
    fn garbage_and_empty_records_are_rejected() {
        for bytes in [&[][..], &[0xFF, 0xFF, 0xFF], &[0x0A, 0x05, 0x01]] {
            assert!(matches!(
                Content::from_plaintext(bytes, DomainId::Password),
                Err(VaultError::MalformedItem)
            ));
        }
    }

    #[test]
    fn wire_format_is_stable() {
        // Field tags are part of the on-disk format: ItemRecord.login = 1,
        // Login.title = 1, Login.username = 2, Login.password = 3.
        let bytes = Login::new("t", "u", "p").into_content().to_plaintext();
        assert_eq!(
            bytes.as_slice(),
            [
                0x0A, 0x09, 0x0A, 0x01, b't', 0x12, 0x01, b'u', 0x1A, 0x01, b'p'
            ]
        );
    }

    #[test]
    fn totp_defaults_and_login_link() {
        let entry = TotpEntry::new("Example", "alice", vec![1; 20]);
        assert_eq!(entry.algorithm(), TotpAlgorithm::Sha1);
        assert_eq!((entry.digits, entry.period), (6, 30));
        assert_eq!(entry.login(), None);
        let linked = entry.for_login(ItemId::from_bytes([5; 16]));
        assert_eq!(linked.login(), Some(ItemId::from_bytes([5; 16])));
    }

    #[test]
    fn debug_output_reveals_nothing() {
        assert_eq!(format!("{:?}", login()), "Login(<redacted>)");
        assert_eq!(
            format!("{:?}", login().into_content()),
            "Content::Login(<redacted>)"
        );
    }
}

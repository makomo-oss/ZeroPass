//! The messages of the local IPC protocol (`docs/spec/ipc.md` §4).
//!
//! The types in this module are the source of truth for the wire format; field
//! tags must never be reused. Messages that carry secrets wipe their contents on
//! drop and print nothing in `Debug`.

use core::fmt;

use prost::{Enumeration, Message, Oneof};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The protocol version this build speaks.
pub const PROTOCOL_VERSION: u32 = 1;

/// Implements a `Debug` that reveals nothing for messages that carry secrets.
macro_rules! redacted_debug {
    ($($ty:ident),* $(,)?) => {$(
        impl fmt::Debug for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($ty), "(<redacted>)"))
            }
        }
    )*};
}

// ---------------------------------------------------------------------------
// Enumerations
// ---------------------------------------------------------------------------

/// A key domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Enumeration)]
#[repr(i32)]
pub enum Domain {
    /// Not set.
    Unspecified = 0,
    /// Logins and secure notes.
    Password = 1,
    /// TOTP seeds.
    Totp = 2,
    /// Passkeys.
    Passkey = 3,
}

/// The kind of an item.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Enumeration)]
#[repr(i32)]
pub enum ItemKind {
    /// Not set.
    Unspecified = 0,
    /// A login.
    Login = 1,
    /// A secure note.
    Note = 2,
    /// A TOTP entry.
    Totp = 3,
    /// A passkey.
    Passkey = 4,
}

/// What a connected client is allowed to do (`docs/spec/ipc.md` §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Enumeration)]
#[repr(i32)]
pub enum Role {
    /// Not set.
    Unspecified = 0,
    /// A user interface: the command-line client or the desktop application.
    Ui = 1,
    /// The native messaging host of the browser extension.
    Bridge = 2,
    /// The agent broker.
    Broker = 3,
    /// The proximity sync daemon.
    Sync = 4,
}

/// The state of a device of the vault.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Enumeration)]
#[repr(i32)]
pub enum DeviceState {
    /// Not set.
    Unspecified = 0,
    /// Another device that may sync.
    Active = 1,
    /// The device the daemon runs on.
    ThisDevice = 2,
    /// A revoked device.
    Revoked = 3,
}

/// Why a request failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Enumeration)]
#[repr(i32)]
pub enum ErrorCode {
    /// An error without a more specific code.
    Internal = 0,
    /// The request is malformed.
    BadRequest = 1,
    /// The client speaks a protocol version the daemon does not.
    UnsupportedProtocol = 2,
    /// The role of this connection may not make the request.
    Denied = 3,
    /// There is no vault file yet.
    NoVault = 4,
    /// A vault file already exists.
    VaultExists = 5,
    /// The domain named in the error is locked.
    Locked = 6,
    /// The vault does not have the domain named in the error.
    DomainUnavailable = 7,
    /// The master password is wrong.
    WrongPassword = 8,
    /// The new master password is too weak.
    WeakPassword = 9,
    /// No such item.
    ItemNotFound = 10,
    /// The item is of a different kind than the request needs.
    WrongItemKind = 11,
    /// The vault has no recovery kit.
    NoRecoveryKit = 12,
    /// The vault already has a recovery kit and `replace` was not set.
    RecoveryKitExists = 13,
    /// The recovery key does not open this vault.
    WrongRecoveryKey = 14,
    /// The user dismissed the biometric prompt.
    UserCancelled = 15,
    /// This device has no hardware key store to unlock the domain with.
    HardwareUnavailable = 16,
    /// No such device, or the device cannot be revoked.
    DeviceNotFound = 17,
    /// A value in the request is not acceptable (for example a bad `otpauth://` URI).
    InvalidInput = 18,
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

/// One request from a client to the daemon.
#[derive(Clone, PartialEq, Message)]
pub struct Request {
    /// The request. Tags 32–79 are reserved (`docs/spec/ipc.md` §4.3).
    #[prost(
        oneof = "request::Body",
        tags = "1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17"
    )]
    pub body: Option<request::Body>,
}

/// The body of a [`Request`].
pub mod request {
    use super::Oneof;

    /// The requests a client can make.
    #[derive(Clone, PartialEq, Oneof)]
    pub enum Body {
        /// Opens the conversation; must be the first request of a connection.
        #[prost(message, tag = "1")]
        Hello(super::Hello),
        /// Asks for the state of the vault.
        #[prost(message, tag = "2")]
        Status(super::Status),
        /// Creates the vault file.
        #[prost(message, tag = "3")]
        CreateVault(super::CreateVault),
        /// Restores access with the recovery key.
        #[prost(message, tag = "4")]
        RecoverVault(super::RecoverVault),
        /// Unlocks a domain.
        #[prost(message, tag = "5")]
        Unlock(super::Unlock),
        /// Locks one domain or all of them.
        #[prost(message, tag = "6")]
        Lock(super::Lock),
        /// Lists the items of a domain, without secrets.
        #[prost(message, tag = "7")]
        ListItems(super::ListItems),
        /// Reads one item.
        #[prost(message, tag = "8")]
        GetItem(super::GetItem),
        /// Adds an item.
        #[prost(message, tag = "9")]
        AddItem(super::AddItem),
        /// Replaces an item.
        #[prost(message, tag = "10")]
        UpdateItem(super::UpdateItem),
        /// Deletes an item.
        #[prost(message, tag = "11")]
        DeleteItem(super::DeleteItem),
        /// Asks for the current one-time code of a TOTP entry.
        #[prost(message, tag = "12")]
        TotpCode(super::TotpCode),
        /// Changes the master password.
        #[prost(message, tag = "13")]
        ChangeMasterPassword(super::ChangeMasterPassword),
        /// Creates a recovery kit.
        #[prost(message, tag = "14")]
        CreateRecoveryKit(super::CreateRecoveryKit),
        /// Lists the devices of the vault.
        #[prost(message, tag = "15")]
        ListDevices(super::ListDevices),
        /// Revokes a device.
        #[prost(message, tag = "16")]
        RevokeDevice(super::RevokeDevice),
        /// Locks everything and stops the daemon.
        #[prost(message, tag = "17")]
        Shutdown(super::Shutdown),
    }
}

/// Opens the conversation.
#[derive(Clone, PartialEq, Message)]
pub struct Hello {
    /// The protocol version the client speaks.
    #[prost(uint32, tag = "1")]
    pub protocol: u32,
    /// A display name of the client, for logs.
    #[prost(string, tag = "2")]
    pub client: String,
}

/// Asks for the state of the vault.
#[derive(Clone, Copy, PartialEq, Message)]
pub struct Status {}

/// Creates the vault file.
#[derive(Clone, PartialEq, Message, Zeroize, ZeroizeOnDrop)]
#[prost(skip_debug)]
pub struct CreateVault {
    /// The master password of the new vault.
    #[prost(string, tag = "1")]
    pub master_password: String,
}

/// Restores access to the vault file with its recovery key.
#[derive(Clone, PartialEq, Message, Zeroize, ZeroizeOnDrop)]
#[prost(skip_debug)]
pub struct RecoverVault {
    /// The recovery key as written down by the user.
    #[prost(string, tag = "1")]
    pub recovery_key: String,
    /// The new master password.
    #[prost(string, tag = "2")]
    pub new_master_password: String,
}

/// Unlocks a domain.
#[derive(Clone, PartialEq, Message, Zeroize, ZeroizeOnDrop)]
#[prost(skip_debug)]
pub struct Unlock {
    /// The domain to unlock.
    #[prost(enumeration = "Domain", tag = "1")]
    pub domain: i32,
    /// The master password; needed for the password domain only.
    #[prost(string, tag = "2")]
    pub master_password: String,
}

/// Locks one domain or all of them.
#[derive(Clone, Copy, PartialEq, Message)]
pub struct Lock {
    /// The domain to lock; all domains when absent.
    #[prost(enumeration = "Domain", optional, tag = "1")]
    pub domain: Option<i32>,
}

/// Lists the items of a domain.
#[derive(Clone, PartialEq, Message)]
pub struct ListItems {
    /// The domain to list.
    #[prost(enumeration = "Domain", tag = "1")]
    pub domain: i32,
    /// Only items matching this text; all items when empty.
    #[prost(string, tag = "2")]
    pub query: String,
}

/// Reads one item.
#[derive(Clone, PartialEq, Message)]
pub struct GetItem {
    /// The item identifier (16 bytes).
    #[prost(bytes = "vec", tag = "1")]
    pub item_id: Vec<u8>,
}

/// Adds an item.
#[derive(Clone, PartialEq, Message)]
pub struct AddItem {
    /// The content of the new item.
    #[prost(message, optional, tag = "1")]
    pub item: Option<NewItem>,
}

/// Replaces the content of an item.
#[derive(Clone, PartialEq, Message)]
pub struct UpdateItem {
    /// The item identifier (16 bytes).
    #[prost(bytes = "vec", tag = "1")]
    pub item_id: Vec<u8>,
    /// The new content; must be of the same kind.
    #[prost(message, optional, tag = "2")]
    pub item: Option<NewItem>,
}

/// Deletes an item.
#[derive(Clone, PartialEq, Message)]
pub struct DeleteItem {
    /// The item identifier (16 bytes).
    #[prost(bytes = "vec", tag = "1")]
    pub item_id: Vec<u8>,
}

/// Asks for the current one-time code of a TOTP entry.
#[derive(Clone, PartialEq, Message)]
pub struct TotpCode {
    /// The item identifier (16 bytes).
    #[prost(bytes = "vec", tag = "1")]
    pub item_id: Vec<u8>,
}

/// Changes the master password.
#[derive(Clone, PartialEq, Message, Zeroize, ZeroizeOnDrop)]
#[prost(skip_debug)]
pub struct ChangeMasterPassword {
    /// The current master password.
    #[prost(string, tag = "1")]
    pub current: String,
    /// The new master password.
    #[prost(string, tag = "2")]
    pub new: String,
}

/// Creates a recovery kit.
#[derive(Clone, Copy, PartialEq, Message)]
pub struct CreateRecoveryKit {
    /// Replace an existing kit; its recovery key stops working.
    #[prost(bool, tag = "1")]
    pub replace: bool,
}

/// Lists the devices of the vault.
#[derive(Clone, Copy, PartialEq, Message)]
pub struct ListDevices {}

/// Revokes a device and replaces the vault keys.
#[derive(Clone, PartialEq, Message)]
pub struct RevokeDevice {
    /// The device identifier.
    #[prost(bytes = "vec", tag = "1")]
    pub device_id: Vec<u8>,
}

/// Locks everything and stops the daemon.
#[derive(Clone, Copy, PartialEq, Message)]
pub struct Shutdown {}

/// The content of an item to add or to replace another with.
#[derive(Clone, PartialEq, Message)]
pub struct NewItem {
    /// The content.
    #[prost(oneof = "new_item::Content", tags = "1, 2, 3")]
    pub content: Option<new_item::Content>,
}

/// The content of a [`NewItem`].
pub mod new_item {
    use super::Oneof;

    /// What can be stored through the IPC. Passkeys are created by the passkey
    /// engine, not handed in.
    #[derive(Clone, PartialEq, Oneof)]
    pub enum Content {
        /// A login.
        #[prost(message, tag = "1")]
        Login(super::Login),
        /// A secure note.
        #[prost(message, tag = "2")]
        Note(super::Note),
        /// A TOTP entry.
        #[prost(message, tag = "3")]
        Totp(super::NewTotp),
    }
}

/// A TOTP entry to store. This is the only way a seed crosses the IPC, and it
/// only goes in.
#[derive(Clone, PartialEq, Message, Zeroize, ZeroizeOnDrop)]
#[prost(skip_debug)]
pub struct NewTotp {
    /// The `otpauth://` URI of the entry.
    #[prost(string, tag = "1")]
    pub otpauth_uri: String,
    /// The login this entry belongs to (16 bytes), if any.
    #[prost(bytes = "vec", optional, tag = "2")]
    pub login_id: Option<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// Item content
// ---------------------------------------------------------------------------

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

/// A free-form secure note.
#[derive(Clone, PartialEq, Message, Zeroize, ZeroizeOnDrop)]
#[prost(skip_debug)]
pub struct Note {
    /// Display name.
    #[prost(string, tag = "1")]
    pub title: String,
    /// The note text.
    #[prost(string, tag = "2")]
    pub body: String,
}

/// What the daemon tells about a TOTP entry. Never the seed.
#[derive(Clone, PartialEq, Message)]
pub struct TotpInfo {
    /// The service that issued the entry.
    #[prost(string, tag = "1")]
    pub issuer: String,
    /// The account name.
    #[prost(string, tag = "2")]
    pub account: String,
    /// The number of digits of a code.
    #[prost(uint32, tag = "3")]
    pub digits: u32,
    /// How long a code is valid, in seconds.
    #[prost(uint32, tag = "4")]
    pub period: u32,
    /// The login this entry belongs to (16 bytes), if any.
    #[prost(bytes = "vec", optional, tag = "5")]
    pub login_id: Option<Vec<u8>>,
}

/// What the daemon tells about a passkey. Never the private key.
#[derive(Clone, PartialEq, Message)]
pub struct PasskeyInfo {
    /// The relying party identifier.
    #[prost(string, tag = "1")]
    pub rp_id: String,
    /// The user name at the relying party.
    #[prost(string, tag = "2")]
    pub user_name: String,
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

/// The response to one [`Request`].
#[derive(Clone, PartialEq, Message)]
pub struct Response {
    /// The response.
    #[prost(oneof = "response::Body", tags = "1, 2, 3, 4, 5, 6, 7, 8, 9, 10")]
    pub body: Option<response::Body>,
}

/// The body of a [`Response`].
pub mod response {
    use super::Oneof;

    /// The responses the daemon can give.
    #[derive(Clone, PartialEq, Oneof)]
    pub enum Body {
        /// The request failed.
        #[prost(message, tag = "1")]
        Error(super::Error),
        /// The request succeeded and has nothing to return.
        #[prost(message, tag = "2")]
        Done(super::Done),
        /// Answer to `Hello`.
        #[prost(message, tag = "3")]
        Hello(super::HelloReply),
        /// Answer to `Status`, `CreateVault` and `RecoverVault`.
        #[prost(message, tag = "4")]
        Status(super::StatusReply),
        /// Answer to `ListItems`.
        #[prost(message, tag = "5")]
        Items(super::Items),
        /// Answer to `GetItem`.
        #[prost(message, tag = "6")]
        Item(super::Item),
        /// Answer to `AddItem`.
        #[prost(message, tag = "7")]
        ItemAdded(super::ItemAdded),
        /// Answer to `TotpCode`.
        #[prost(message, tag = "8")]
        TotpCode(super::TotpCodeReply),
        /// Answer to `CreateRecoveryKit`.
        #[prost(message, tag = "9")]
        RecoveryKit(super::RecoveryKit),
        /// Answer to `ListDevices`.
        #[prost(message, tag = "10")]
        Devices(super::Devices),
    }
}

/// A failed request.
#[derive(Clone, PartialEq, Message)]
pub struct Error {
    /// Why the request failed.
    #[prost(enumeration = "ErrorCode", tag = "1")]
    pub code: i32,
    /// A sentence for people. Never contains secrets.
    #[prost(string, tag = "2")]
    pub message: String,
    /// The domain the error is about, for `Locked` and `DomainUnavailable`.
    #[prost(enumeration = "Domain", optional, tag = "3")]
    pub domain: Option<i32>,
}

impl Error {
    /// Creates an error without a domain.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code: code as i32,
            message: message.into(),
            domain: None,
        }
    }

    /// Creates an error about a domain.
    pub fn about(code: ErrorCode, domain: Domain, message: impl Into<String>) -> Self {
        Self {
            code: code as i32,
            message: message.into(),
            domain: Some(domain as i32),
        }
    }
}

/// A successful request with nothing to return.
#[derive(Clone, Copy, PartialEq, Message)]
pub struct Done {}

/// Answer to [`Hello`].
#[derive(Clone, PartialEq, Message)]
pub struct HelloReply {
    /// The protocol version the daemon speaks.
    #[prost(uint32, tag = "1")]
    pub protocol: u32,
    /// The version of the daemon.
    #[prost(string, tag = "2")]
    pub daemon_version: String,
    /// The role given to this connection.
    #[prost(enumeration = "Role", tag = "3")]
    pub role: i32,
}

/// The state of the vault.
#[derive(Clone, PartialEq, Message)]
pub struct StatusReply {
    /// Whether the vault file exists.
    #[prost(bool, tag = "1")]
    pub vault_exists: bool,
    /// The vault identifier; empty without a vault.
    #[prost(bytes = "vec", tag = "2")]
    pub vault_id: Vec<u8>,
    /// The identifier of this device; empty without a vault.
    #[prost(bytes = "vec", tag = "3")]
    pub device_id: Vec<u8>,
    /// One entry per key domain.
    #[prost(message, repeated, tag = "4")]
    pub domains: Vec<DomainStatus>,
    /// Whether a recovery kit exists.
    #[prost(bool, tag = "5")]
    pub has_recovery_kit: bool,
    /// Whether the daemon runs in a sandbox without network access.
    #[prost(bool, tag = "6")]
    pub sandboxed: bool,
}

/// The state of one key domain.
#[derive(Clone, Copy, PartialEq, Message)]
pub struct DomainStatus {
    /// The domain.
    #[prost(enumeration = "Domain", tag = "1")]
    pub domain: i32,
    /// Whether the vault has this domain.
    #[prost(bool, tag = "2")]
    pub available: bool,
    /// Whether the domain is unlocked right now.
    #[prost(bool, tag = "3")]
    pub unlocked: bool,
}

/// Answer to [`ListItems`].
#[derive(Clone, PartialEq, Message)]
pub struct Items {
    /// The items, sorted by title.
    #[prost(message, repeated, tag = "1")]
    pub items: Vec<ItemSummary>,
}

/// What a list shows of an item. No secrets.
#[derive(Clone, PartialEq, Message)]
pub struct ItemSummary {
    /// The item identifier (16 bytes).
    #[prost(bytes = "vec", tag = "1")]
    pub item_id: Vec<u8>,
    /// The kind of the item.
    #[prost(enumeration = "ItemKind", tag = "2")]
    pub kind: i32,
    /// The display name.
    #[prost(string, tag = "3")]
    pub title: String,
    /// The user or account name, if the kind has one.
    #[prost(string, tag = "4")]
    pub username: String,
    /// The URLs of a login.
    #[prost(string, repeated, tag = "5")]
    pub urls: Vec<String>,
}

/// Answer to [`GetItem`].
#[derive(Clone, PartialEq, Message)]
pub struct Item {
    /// The item identifier (16 bytes).
    #[prost(bytes = "vec", tag = "1")]
    pub item_id: Vec<u8>,
    /// The content.
    #[prost(oneof = "item::Content", tags = "2, 3, 4, 5")]
    pub content: Option<item::Content>,
}

/// The content of an [`Item`].
pub mod item {
    use super::Oneof;

    /// What the daemon returns of an item (`docs/spec/ipc.md` §6).
    #[derive(Clone, PartialEq, Oneof)]
    pub enum Content {
        /// A login, with its password.
        #[prost(message, tag = "2")]
        Login(super::Login),
        /// A secure note, with its text.
        #[prost(message, tag = "3")]
        Note(super::Note),
        /// A TOTP entry, without its seed.
        #[prost(message, tag = "4")]
        Totp(super::TotpInfo),
        /// A passkey, without its private key.
        #[prost(message, tag = "5")]
        Passkey(super::PasskeyInfo),
    }
}

/// Answer to [`AddItem`].
#[derive(Clone, PartialEq, Message)]
pub struct ItemAdded {
    /// The identifier of the new item (16 bytes).
    #[prost(bytes = "vec", tag = "1")]
    pub item_id: Vec<u8>,
}

/// Answer to [`TotpCode`].
#[derive(Clone, PartialEq, Message, Zeroize, ZeroizeOnDrop)]
#[prost(skip_debug)]
pub struct TotpCodeReply {
    /// The current code.
    #[prost(string, tag = "1")]
    pub code: String,
    /// How long the code remains valid, in seconds.
    #[prost(uint32, tag = "2")]
    pub seconds_remaining: u32,
}

/// Answer to [`CreateRecoveryKit`].
#[derive(Clone, PartialEq, Message, Zeroize, ZeroizeOnDrop)]
#[prost(skip_debug)]
pub struct RecoveryKit {
    /// The recovery key to write down. It is not shown again.
    #[prost(string, tag = "1")]
    pub recovery_key: String,
}

/// Answer to [`ListDevices`].
#[derive(Clone, PartialEq, Message)]
pub struct Devices {
    /// The devices of the vault.
    #[prost(message, repeated, tag = "1")]
    pub devices: Vec<Device>,
}

/// One device of the vault.
#[derive(Clone, PartialEq, Message)]
pub struct Device {
    /// The device identifier.
    #[prost(bytes = "vec", tag = "1")]
    pub device_id: Vec<u8>,
    /// The name the device was given.
    #[prost(string, tag = "2")]
    pub name: String,
    /// The state of the device.
    #[prost(enumeration = "DeviceState", tag = "3")]
    pub state: i32,
    /// How many changes made by that device this device holds.
    #[prost(uint64, tag = "4")]
    pub changes_held: u64,
}

redacted_debug!(
    CreateVault,
    RecoverVault,
    Unlock,
    ChangeMasterPassword,
    NewTotp,
    Login,
    Note,
    TotpCodeReply,
    RecoveryKit,
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_round_trip() {
        let request = Request {
            body: Some(request::Body::AddItem(AddItem {
                item: Some(NewItem {
                    content: Some(new_item::Content::Login(Login {
                        title: "Example".into(),
                        username: "alice".into(),
                        password: "hunter2-hunter2".into(),
                        urls: vec!["https://example.com".into()],
                        notes: String::new(),
                    })),
                }),
            })),
        };
        let bytes = request.encode_to_vec();
        assert_eq!(Request::decode(bytes.as_slice()).unwrap(), request);
    }

    #[test]
    fn secrets_are_not_printed() {
        let request = Request {
            body: Some(request::Body::Unlock(Unlock {
                domain: Domain::Password as i32,
                master_password: "correct horse battery".into(),
            })),
        };
        let printed = format!("{request:?}");
        assert!(!printed.contains("correct horse"), "{printed}");
        let reply = Response {
            body: Some(response::Body::RecoveryKit(RecoveryKit {
                recovery_key: "ABCD-EFGH".into(),
            })),
        };
        assert!(!format!("{reply:?}").contains("ABCD"));
    }

    #[test]
    fn unknown_requests_decode_to_an_empty_body() {
        // A request with only a field from a reserved range (tag 40).
        let bytes = [0xC2, 0x02, 0x00];
        assert_eq!(Request::decode(bytes.as_slice()).unwrap().body, None);
    }
}

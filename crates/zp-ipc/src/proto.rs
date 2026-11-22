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
    /// The key agent: asks the platform's hardware key store on behalf of
    /// the vault daemon (`docs/spec/ipc.md` §13).
    KeyAgent = 5,
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
    /// Sync data handed in was refused: malformed, not signed by a device of
    /// the vault, or against the rules of the sync protocol.
    SyncRejected = 19,
    /// The vault already holds a passkey that the relying party excludes
    /// (`docs/spec/passkey.md` §9).
    CredentialExcluded = 20,
    /// None of the signature algorithms the relying party accepts is one
    /// ZeroPass makes passkeys with.
    UnsupportedAlgorithm = 21,
    /// Revoking from this device would leave the TOTP or passkey keys that
    /// other devices hold unreplaced, or lose them if the revoked device holds
    /// the last copy: this device does not have them (ADR-0011).
    KeysAtRisk = 22,
    /// Other devices of the vault seem to have the domain: get its keys from
    /// one of them instead of making it anew (ADR-0011).
    DomainElsewhere = 23,
    /// Something was written with a key that has not reached this device
    /// (ADR-0011): get the keys from another device, or sync.
    KeysMissing = 24,
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

/// One request from a client to the daemon.
#[derive(Clone, PartialEq, Message)]
pub struct Request {
    /// The request. Tags 48–63 and 66–79 are reserved (`docs/spec/ipc.md` §4.3).
    #[prost(
        oneof = "request::Body",
        tags = "1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 64, 65, 66, 80, 81, 82, 83, 96, 97, 100, 101, 102, 103, 104, 105"
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
        /// Sync: asks for the identity of this device on the sync channel.
        #[prost(message, tag = "32")]
        SyncIdentity(super::SyncIdentity),
        /// Sync: asks for the device registry.
        #[prost(message, tag = "33")]
        SyncRegistry(super::SyncRegistry),
        /// Sync: hands in device records and revocations received from a peer.
        #[prost(message, tag = "34")]
        SyncMergeRegistry(super::SyncMergeRegistry),
        /// Sync: asks for the version vector.
        #[prost(message, tag = "35")]
        SyncVector(super::SyncVector),
        /// Sync: asks for the ops of one device after a sequence number.
        #[prost(message, tag = "36")]
        SyncOpsAfter(super::SyncOpsAfter),
        /// Sync: hands in ops received from a peer.
        #[prost(message, tag = "37")]
        SyncApply(super::SyncApply),
        /// Sync: asks for the key updates.
        #[prost(message, tag = "38")]
        SyncKeyUpdates(super::SyncKeyUpdates),
        /// Sync: hands in key updates received from a peer.
        #[prost(message, tag = "39")]
        SyncMergeKeyUpdates(super::SyncMergeKeyUpdates),
        /// Pairing: creates a pairing offer to show to the other device.
        #[prost(message, tag = "40")]
        PairOffer(super::PairOffer),
        /// Pairing: admits the device that connected with the offer. Starts a
        /// relay (`docs/spec/ipc.md` §11).
        #[prost(message, tag = "41")]
        PairAdmit(super::PairAdmit),
        /// Pairing: joins a vault with an offer shown by another device. Starts
        /// a relay.
        #[prost(message, tag = "42")]
        PairJoin(super::PairJoin),
        /// Relay: on a device that is already a member, asks the device at the
        /// other end of the relayed link for the TOTP and passkey keys and
        /// takes them in (ADR-0011).
        #[prost(message, tag = "46")]
        PairReceiveKeys(super::PairReceiveKeys),
        /// Relay: makes this connection the uplink of a relay.
        #[prost(message, tag = "43")]
        RelayAttach(super::RelayAttach),
        /// Relay, uplink: bytes that arrived from the other device.
        #[prost(message, tag = "44")]
        LinkData(super::LinkData),
        /// Relay, uplink: the user's answer to `PairConfirmRequest`.
        #[prost(message, tag = "45")]
        PairConfirm(super::PairConfirm),
        /// Makes an encrypted export of the whole vault (`docs/spec/export.md`).
        #[prost(message, tag = "18")]
        ExportVault(super::ExportVault),
        /// Adds the items of an encrypted export to the vault.
        #[prost(message, tag = "19")]
        ImportExport(super::ImportExport),
        /// Sync daemon: asks where it can be reached and what it can use.
        #[prost(message, tag = "80")]
        SyncdStatus(super::SyncdStatus),
        /// Sync daemon: syncs with the devices nearby now and reports.
        #[prost(message, tag = "81")]
        SyncNow(super::SyncNow),
        /// Sync daemon: waits for a device that wants to pair and relays its
        /// link. Starts a relay.
        #[prost(message, tag = "82")]
        PairListen(super::PairListen),
        /// Sync daemon: connects to a device to join its vault and relays the
        /// link. Starts a relay.
        #[prost(message, tag = "83")]
        PairConnect(super::PairConnect),
        /// Extension bridge: the logins that match a web page
        /// (`docs/spec/extension.md` §4).
        #[prost(message, tag = "100")]
        BridgeFind(super::BridgeFind),
        /// Extension bridge: the user name and password of one login, for the
        /// page it matches.
        #[prost(message, tag = "101")]
        BridgeFill(super::BridgeFill),
        /// Extension bridge: the current one-time code of the TOTP entry tied
        /// to a login of the page, after the user is verified anew.
        #[prost(message, tag = "102")]
        BridgeTotp(super::BridgeTotp),
        /// Extension bridge: saves a new login for the page.
        #[prost(message, tag = "103")]
        BridgeSave(super::BridgeSave),
        /// Extension bridge: replaces the password of a login of the page.
        #[prost(message, tag = "104")]
        BridgeUpdate(super::BridgeUpdate),
        /// Extension bridge: whether what the user typed into the page is
        /// already in the vault.
        #[prost(message, tag = "105")]
        BridgeCompare(super::BridgeCompare),
        /// Makes a passkey for a web page (`navigator.credentials.create`,
        /// `docs/spec/passkey.md` §9). The user is verified anew.
        #[prost(message, tag = "64")]
        PasskeyCreate(super::PasskeyCreate),
        /// Signs for a web page with one of its passkeys
        /// (`navigator.credentials.get`). The user is verified anew.
        #[prost(message, tag = "65")]
        PasskeyGet(super::PasskeyGet),
        /// Makes the TOTP or passkey domain on this device, for a vault that
        /// has it nowhere (ADR-0011). Windows Hello asks.
        #[prost(message, tag = "66")]
        SetUpDomain(super::SetUpDomain),
        /// Key agent: offers the platform's hardware key store to the vault
        /// daemon. Starts a relay.
        #[prost(message, tag = "96")]
        KeyAgentAttach(super::KeyAgentAttach),
        /// Relay of the key agent, uplink: the answer to a `KeyAgentRequest`.
        #[prost(message, tag = "97")]
        KeyAgentReply(super::KeyAgentReply),
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
    /// Create the vault even if the hardware key store cannot be used: then
    /// it has no TOTP and passkey domains on this device (ADR-0011). Without
    /// this, the request fails with `HARDWARE_UNAVAILABLE`.
    #[prost(bool, tag = "2")]
    pub without_hardware: bool,
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
    /// Revoke even though this device lacks a TOTP or passkey domain that
    /// other devices seem to have. Without this, the request fails with
    /// `KEYS_AT_RISK` in that case.
    #[prost(bool, tag = "2")]
    pub even_without_keys: bool,
}

/// Makes a hardware-bound domain on this device (ADR-0011 §2).
#[derive(Clone, Copy, PartialEq, Message)]
pub struct SetUpDomain {
    /// The TOTP or the passkey domain.
    #[prost(enumeration = "Domain", tag = "1")]
    pub domain: i32,
}

/// Locks everything and stops the daemon.
#[derive(Clone, Copy, PartialEq, Message)]
pub struct Shutdown {}

// ---------------------------------------------------------------------------
// Sync requests (`docs/spec/ipc.md` §10)
//
// These mirror `zp_sync::OpLog`. Registries, version vectors, ops and key
// updates travel in the encoding of the sync session (`docs/spec/sync.md` §7),
// as opaque bytes. All of it is ciphertext, signatures and public keys.
// ---------------------------------------------------------------------------

/// Asks for the identity of this device on the sync channel.
#[derive(Clone, Copy, PartialEq, Message)]
pub struct SyncIdentity {}

/// Asks for the device registry.
#[derive(Clone, Copy, PartialEq, Message)]
pub struct SyncRegistry {}

/// Hands in device records and revocations received from a peer.
#[derive(Clone, PartialEq, Message)]
pub struct SyncMergeRegistry {
    /// The records and revocations (`zp_sync::encode_registry`).
    #[prost(bytes = "vec", tag = "1")]
    pub registry: Vec<u8>,
}

/// Asks for the version vector.
#[derive(Clone, Copy, PartialEq, Message)]
pub struct SyncVector {}

/// Asks for the ops written by one device.
#[derive(Clone, PartialEq, Message)]
pub struct SyncOpsAfter {
    /// The device that wrote the ops.
    #[prost(bytes = "vec", tag = "1")]
    pub device_id: Vec<u8>,
    /// Only ops with a higher sequence number.
    #[prost(uint64, tag = "2")]
    pub after_seq: u64,
    /// At most this many ops.
    #[prost(uint32, tag = "3")]
    pub limit: u32,
}

/// Hands in ops received from a peer. All of them are stored, or none.
#[derive(Clone, PartialEq, Message)]
pub struct SyncApply {
    /// The ops (`zp_sync::encode_ops`).
    #[prost(bytes = "vec", tag = "1")]
    pub ops: Vec<u8>,
}

/// Asks for the key updates.
#[derive(Clone, Copy, PartialEq, Message)]
pub struct SyncKeyUpdates {}

/// Hands in key updates received from a peer. All are stored, or none.
#[derive(Clone, PartialEq, Message)]
pub struct SyncMergeKeyUpdates {
    /// The key updates (`zp_sync::encode_key_updates`).
    #[prost(bytes = "vec", tag = "1")]
    pub updates: Vec<u8>,
}

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
// Pairing and relays (`docs/spec/ipc.md` §11)
// ---------------------------------------------------------------------------

/// Creates a pairing offer. Every domain of the vault must be unlocked, and
/// stays unlocked until the offer has been used or has expired.
#[derive(Clone, PartialEq, Message)]
pub struct PairOffer {
    /// Where the other device can reach this one on the local network
    /// (`address:port`), to be put into the offer.
    #[prost(string, repeated, tag = "1")]
    pub hints: Vec<String>,
}

/// Admits the device at the other end of the link that the client relays,
/// using the offer created with [`PairOffer`].
#[derive(Clone, Copy, PartialEq, Message)]
pub struct PairAdmit {}

/// Joins a vault: creates this device's vault file from what the device at
/// the other end of the relayed link grants.
#[derive(Clone, PartialEq, Message, Zeroize, ZeroizeOnDrop)]
#[prost(skip_debug)]
pub struct PairJoin {
    /// The pairing offer shown by the other device, as text.
    #[prost(string, tag = "1")]
    pub offer: String,
    /// The name of this device, shown to the user of the other device.
    #[prost(string, tag = "2")]
    pub device_name: String,
    /// The master password of the new vault file.
    #[prost(string, tag = "3")]
    pub master_password: String,
    /// Join even if the hardware key store cannot be used, as for
    /// [`CreateVault::without_hardware`].
    #[prost(bool, tag = "4")]
    pub without_hardware: bool,
}

/// Asks the device at the other end of the relayed link for the TOTP and
/// passkey keys (ADR-0011). Windows Hello verifies the user here when a domain
/// is new to this device.
#[derive(Clone, PartialEq, Message, Zeroize, ZeroizeOnDrop)]
#[prost(skip_debug)]
pub struct PairReceiveKeys {
    /// The pairing offer shown by the other device, as text.
    #[prost(string, tag = "1")]
    pub offer: String,
}

/// Makes this connection the uplink of a relay: after the answer, the client
/// only sends, and the daemon only reads, until the client closes it.
#[derive(Clone, Copy, PartialEq, Message)]
pub struct RelayAttach {
    /// The relay, as named in [`RelayOpened`].
    #[prost(uint64, tag = "1")]
    pub relay_id: u64,
}

/// Bytes of the relayed link. Ciphertext of the pairing channel: the relaying
/// process cannot read it.
#[derive(Clone, PartialEq, Message)]
pub struct LinkData {
    /// The bytes, in order.
    #[prost(bytes = "vec", tag = "1")]
    pub data: Vec<u8>,
}

/// The user's answer to [`PairConfirmRequest`].
#[derive(Clone, Copy, PartialEq, Message)]
pub struct PairConfirm {
    /// Whether the device may join.
    #[prost(bool, tag = "1")]
    pub approved: bool,
}

// ---------------------------------------------------------------------------
// Sync daemon (`docs/spec/ipc.md` §12)
// ---------------------------------------------------------------------------

/// Asks the sync daemon where it can be reached and what it can use.
#[derive(Clone, Copy, PartialEq, Message)]
pub struct SyncdStatus {}

/// Asks the sync daemon to sync with the devices nearby now.
#[derive(Clone, Copy, PartialEq, Message)]
pub struct SyncNow {
    /// How long to look for the other devices, in seconds.
    #[prost(uint32, tag = "1")]
    pub seconds: u32,
}

/// Asks the sync daemon to wait for a device that wants to pair. The pairing
/// code itself is not handed over: its secret stays with the vault daemon and
/// the user interface.
#[derive(Clone, PartialEq, Message)]
pub struct PairListen {
    /// The tag joining devices look for over Bluetooth LE
    /// (`zp_pairing::qr::pairing_tag`, 8 bytes).
    #[prost(bytes = "vec", tag = "1")]
    pub tag: Vec<u8>,
    /// How long to wait, in seconds.
    #[prost(uint32, tag = "2")]
    pub seconds: u32,
}

/// Asks the sync daemon to connect to a device whose pairing code this device
/// scanned. Only the addresses from the code are handed over.
#[derive(Clone, PartialEq, Message)]
pub struct PairConnect {
    /// The addresses (`address:port`) to try, in order.
    #[prost(string, repeated, tag = "1")]
    pub addresses: Vec<String>,
}

// ---------------------------------------------------------------------------
// Key agent (`docs/spec/ipc.md` §13)
// ---------------------------------------------------------------------------

/// Offers the platform's hardware key store to the vault daemon, for as long
/// as the relay lasts. The daemon answers `Listening` once it will use it.
#[derive(Clone, Copy, PartialEq, Message)]
pub struct KeyAgentAttach {}

/// Something the vault daemon asks the platform's hardware key store.
#[derive(Clone, PartialEq, Message)]
pub struct KeyAgentRequest {
    /// Repeated in the reply.
    #[prost(uint64, tag = "1")]
    pub id: u64,
    /// What is asked.
    #[prost(oneof = "key_agent_request::Ask", tags = "2, 3")]
    pub ask: Option<key_agent_request::Ask>,
}

/// The oneof of [`KeyAgentRequest`].
pub mod key_agent_request {
    use prost::Oneof;

    /// What the vault daemon asks.
    #[derive(Clone, PartialEq, Oneof)]
    pub enum Ask {
        /// Whether this device has a hardware key store.
        #[prost(message, tag = "2")]
        Probe(super::KeyAgentProbe),
        /// A signature, which verifies the user.
        #[prost(message, tag = "3")]
        Sign(super::KeyAgentSign),
    }
}

/// Asks whether this device has a hardware key store.
#[derive(Clone, Copy, PartialEq, Message)]
pub struct KeyAgentProbe {
    /// Create the store's key if it does not exist yet, which may ask the user.
    #[prost(bool, tag = "1")]
    pub create: bool,
}

/// Asks the hardware key store to sign after verifying the user.
#[derive(Clone, PartialEq, Message)]
pub struct KeyAgentSign {
    /// What to sign. Not a secret: it is stored beside the wrapped key.
    #[prost(bytes = "vec", tag = "1")]
    pub challenge: Vec<u8>,
    /// The public key to seal the signature to (`zp_crypto::seal_to`, with the
    /// challenge as the context): only the process that asked can open it.
    #[prost(bytes = "vec", tag = "2")]
    pub reply_key: Vec<u8>,
}

/// The key agent's answer to a [`KeyAgentRequest`].
#[derive(Clone, PartialEq, Message)]
pub struct KeyAgentReply {
    /// The `id` of the request.
    #[prost(uint64, tag = "1")]
    pub id: u64,
    /// The answer.
    #[prost(oneof = "key_agent_reply::Outcome", tags = "2, 3, 4")]
    pub outcome: Option<key_agent_reply::Outcome>,
}

/// The oneof of [`KeyAgentReply`].
pub mod key_agent_reply {
    use prost::Oneof;

    /// What the hardware key store answered.
    #[derive(Clone, PartialEq, Oneof)]
    pub enum Outcome {
        /// Answer to `Probe`: there is a hardware key store.
        #[prost(message, tag = "2")]
        Available(super::KeyStoreAvailable),
        /// Answer to `Sign`: the signature, sealed to `reply_key`.
        #[prost(bytes = "vec", tag = "3")]
        Signature(Vec<u8>),
        /// It did not work.
        #[prost(message, tag = "4")]
        Failed(super::KeyStoreFailure),
    }
}

/// This device has a hardware key store.
#[derive(Clone, Copy, PartialEq, Message)]
pub struct KeyStoreAvailable {
    /// Which implementation it is: the first byte of the key slots it wraps
    /// (`docs/spec/crypto.md` §7).
    #[prost(uint32, tag = "1")]
    pub implementation_id: u32,
}

/// Why the hardware key store did not answer as asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Enumeration)]
#[repr(i32)]
pub enum KeyStoreProblem {
    /// Not set.
    Unspecified = 0,
    /// This device has no hardware key store, or the user has not set it up.
    Unavailable = 1,
    /// The user dismissed the prompt or was not recognised.
    UserCancelled = 2,
    /// The store reported an error.
    Platform = 3,
}

/// The hardware key store did not answer as asked.
#[derive(Clone, PartialEq, Message)]
pub struct KeyStoreFailure {
    /// What went wrong.
    #[prost(enumeration = "KeyStoreProblem", tag = "1")]
    pub problem: i32,
    /// A sentence for people.
    #[prost(string, tag = "2")]
    pub message: String,
}

impl KeyAgentReply {
    /// A reply that says the store did not answer as asked.
    pub fn failed(id: u64, problem: KeyStoreProblem, message: impl Into<String>) -> Self {
        Self {
            id,
            outcome: Some(key_agent_reply::Outcome::Failed(KeyStoreFailure {
                problem: problem as i32,
                message: message.into(),
            })),
        }
    }
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
    #[prost(
        oneof = "response::Body",
        tags = "1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31"
    )]
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
        /// Answer to `SyncIdentity`.
        #[prost(message, tag = "11")]
        SyncIdentity(super::SyncIdentityReply),
        /// Answer to `SyncRegistry`, `SyncVector`, `SyncOpsAfter` and
        /// `SyncKeyUpdates`.
        #[prost(message, tag = "12")]
        SyncData(super::SyncData),
        /// Answer to `SyncMergeRegistry`, `SyncApply` and `SyncMergeKeyUpdates`.
        #[prost(message, tag = "13")]
        SyncMerged(super::SyncMerged),
        /// Answer to `PairOffer`.
        #[prost(message, tag = "14")]
        PairOffered(super::PairOffered),
        /// Relay, downlink: the relay is open; attach the uplink.
        #[prost(message, tag = "15")]
        RelayOpened(super::RelayOpened),
        /// Relay, downlink: bytes to send to the other device.
        #[prost(message, tag = "16")]
        LinkData(super::LinkData),
        /// Relay, downlink: ask the user whether this device may join.
        #[prost(message, tag = "17")]
        PairConfirmRequest(super::PairConfirmRequest),
        /// Relay, downlink: pairing is complete. The last message of the relay.
        #[prost(message, tag = "18")]
        PairDone(super::PairDone),
        /// Answer to `SyncdStatus`.
        #[prost(message, tag = "19")]
        SyncdStatus(super::SyncdStatusReply),
        /// Answer to `SyncNow`.
        #[prost(message, tag = "20")]
        SyncResults(super::SyncResults),
        /// Relay of the sync daemon: the link to the other device ended. The
        /// last message of the relay.
        #[prost(message, tag = "21")]
        LinkEnded(super::LinkEnded),
        /// Relay of `PairListen`: the sync daemon now waits for the device. The
        /// pairing code can be shown from here on.
        #[prost(message, tag = "22")]
        Listening(super::Listening),
        /// Answer to `ExportVault`.
        #[prost(message, tag = "27")]
        Exported(super::Exported),
        /// Answer to `ImportExport`.
        #[prost(message, tag = "28")]
        ImportedItems(super::ImportedItems),
        /// Answer to `BridgeFind`.
        #[prost(message, tag = "24")]
        BridgeLogins(super::BridgeLogins),
        /// Answer to `BridgeFill`.
        #[prost(message, tag = "25")]
        BridgeCredential(super::BridgeCredential),
        /// Answer to `BridgeCompare`.
        #[prost(message, tag = "26")]
        BridgeComparison(super::BridgeComparison),
        /// Answer to `PasskeyCreate`.
        #[prost(message, tag = "29")]
        PasskeyCreated(super::PasskeyCreated),
        /// Answer to `PasskeyGet`: the assertion.
        #[prost(message, tag = "30")]
        PasskeyAssertion(super::PasskeyAssertion),
        /// Answer to `PasskeyGet` when several passkeys fit and none was
        /// picked.
        #[prost(message, tag = "31")]
        PasskeyChoices(super::PasskeyChoices),
        /// Relay of the key agent, downlink: something to ask the platform's
        /// hardware key store.
        #[prost(message, tag = "23")]
        KeyAgentRequest(super::KeyAgentRequest),
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
    /// The process identifier of the daemon, for diagnostics.
    #[prost(uint32, tag = "7")]
    pub pid: u32,
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
    /// For a domain this device does not have: whether there are signs that
    /// other devices of the vault have it (its keys came with the pairing, or
    /// the vault holds its items or key updates). Then its keys are to be
    /// received from such a device rather than created here (ADR-0011).
    #[prost(bool, tag = "4")]
    pub elsewhere: bool,
}

/// Answer to [`ListItems`].
#[derive(Clone, PartialEq, Message)]
pub struct Items {
    /// The items, sorted by title.
    #[prost(message, repeated, tag = "1")]
    pub items: Vec<ItemSummary>,
    /// How many live items of the domain are left out because the keys held
    /// here do not open them (ADR-0011).
    #[prost(uint32, tag = "2")]
    pub unreadable: u32,
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

/// Answer to [`SyncIdentity`]: who this device is on the sync channel.
///
/// The channel key authenticates the device to its peers. It is not a vault
/// key: it opens no item, and what a peer sends is still verified against the
/// signatures of the devices in the registry.
#[derive(Clone, PartialEq, Message, Zeroize, ZeroizeOnDrop)]
#[prost(skip_debug)]
pub struct SyncIdentityReply {
    /// The vault identifier.
    #[prost(bytes = "vec", tag = "1")]
    pub vault_id: Vec<u8>,
    /// The identifier of this device.
    #[prost(bytes = "vec", tag = "2")]
    pub device_id: Vec<u8>,
    /// The private channel key of this device (32 bytes).
    #[prost(bytes = "vec", tag = "3")]
    pub channel_key: Vec<u8>,
}

/// Sync data in the encoding of the sync session.
#[derive(Clone, PartialEq, Message)]
pub struct SyncData {
    /// A registry, a version vector, ops or key updates, as asked for.
    #[prost(bytes = "vec", tag = "1")]
    pub data: Vec<u8>,
}

/// What handing in sync data changed.
#[derive(Clone, Copy, PartialEq, Message)]
pub struct SyncMerged {
    /// Ops or key updates that were new and have been stored; 1 if the
    /// registry changed.
    #[prost(uint64, tag = "1")]
    pub added: u64,
    /// Ops that were already held.
    #[prost(uint64, tag = "2")]
    pub duplicates: u64,
    /// Stored ops that became the current version of their item.
    #[prost(uint64, tag = "3")]
    pub became_current: u64,
}

/// Answer to [`PairOffer`].
#[derive(Clone, PartialEq, Message, Zeroize, ZeroizeOnDrop)]
#[prost(skip_debug)]
pub struct PairOffered {
    /// The offer as text, to show as it is and as a QR code. It contains a
    /// one-time secret: whoever sees it within its lifetime can ask to join.
    #[prost(string, tag = "1")]
    pub offer: String,
    /// How long the offer is valid, in seconds.
    #[prost(uint32, tag = "2")]
    pub lifetime_secs: u32,
}

/// The relay is open.
#[derive(Clone, Copy, PartialEq, Message)]
pub struct RelayOpened {
    /// The name of the relay, for [`RelayAttach`].
    #[prost(uint64, tag = "1")]
    pub relay_id: u64,
}

/// Asks the user whether the device that connected may join the vault.
#[derive(Clone, PartialEq, Message)]
pub struct PairConfirmRequest {
    /// The identifier the device chose for itself.
    #[prost(bytes = "vec", tag = "1")]
    pub device_id: Vec<u8>,
    /// The name it gave.
    #[prost(string, tag = "2")]
    pub name: String,
    /// Whether it is a member asking for the TOTP and passkey keys, rather
    /// than a new device asking to join (ADR-0011).
    #[prost(bool, tag = "3")]
    pub keys_only: bool,
}

/// Pairing is complete.
#[derive(Clone, PartialEq, Message)]
pub struct PairDone {
    /// The device that joined (for the existing device), or this device (for
    /// the joining one).
    #[prost(bytes = "vec", tag = "1")]
    pub device_id: Vec<u8>,
    /// The name of the device that joined.
    #[prost(string, tag = "2")]
    pub name: String,
    /// The vault.
    #[prost(bytes = "vec", tag = "3")]
    pub vault_id: Vec<u8>,
    /// Why the first sync did not complete; empty if it did. The device is a
    /// member either way and catches up at the next sync.
    #[prost(string, tag = "4")]
    pub first_sync_error: String,
    /// Changes sent in the first sync.
    #[prost(uint64, tag = "5")]
    pub sent: u64,
    /// Changes received in the first sync.
    #[prost(uint64, tag = "6")]
    pub received: u64,
    /// On the device that asked for the keys (`PairReceiveKeys`): the domains
    /// that gained keys.
    #[prost(enumeration = "Domain", repeated, tag = "7")]
    pub domains: Vec<i32>,
    /// On the device that handed the keys: the other device was a member
    /// asking for the TOTP and passkey keys, not a new device joining.
    #[prost(bool, tag = "8")]
    pub keys_only: bool,
}

/// Answer to [`SyncdStatus`].
#[derive(Clone, PartialEq, Message)]
pub struct SyncdStatusReply {
    /// Where other devices reach this one on the local network
    /// (`address:port`), to put into a pairing code.
    #[prost(string, repeated, tag = "1")]
    pub lan_endpoints: Vec<String>,
    /// The transports in use (`lan`, `ble`).
    #[prost(string, repeated, tag = "2")]
    pub transports: Vec<String>,
    /// Transports that could not be used, and why.
    #[prost(string, repeated, tag = "3")]
    pub problems: Vec<String>,
    /// Whether the sync daemon is connected to the vault daemon and syncing.
    #[prost(bool, tag = "4")]
    pub syncing: bool,
    /// Why not, if it is not.
    #[prost(string, tag = "5")]
    pub not_syncing_because: String,
    /// The process identifier of the sync daemon, for diagnostics.
    #[prost(uint32, tag = "6")]
    pub pid: u32,
}

/// Answer to [`SyncNow`].
#[derive(Clone, PartialEq, Message)]
pub struct SyncResults {
    /// How many other active devices the vault has.
    #[prost(uint32, tag = "1")]
    pub other_devices: u32,
    /// One entry per session that took place.
    #[prost(message, repeated, tag = "2")]
    pub results: Vec<SyncResult>,
}

/// One sync session.
#[derive(Clone, PartialEq, Message)]
pub struct SyncResult {
    /// The other device, if it was identified.
    #[prost(bytes = "vec", tag = "1")]
    pub device_id: Vec<u8>,
    /// Its name.
    #[prost(string, tag = "2")]
    pub name: String,
    /// Changes sent.
    #[prost(uint64, tag = "3")]
    pub sent: u64,
    /// Changes received.
    #[prost(uint64, tag = "4")]
    pub received: u64,
    /// Why the session failed; empty if it completed.
    #[prost(string, tag = "5")]
    pub error: String,
}

/// The sync daemon waits for the device that wants to pair.
#[derive(Clone, Copy, PartialEq, Message)]
pub struct Listening {}

/// The relayed link ended.
#[derive(Clone, PartialEq, Message)]
pub struct LinkEnded {
    /// Why, if it did not simply close.
    #[prost(string, tag = "1")]
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Extension bridge (`docs/spec/extension.md` §4)
// ---------------------------------------------------------------------------

/// The logins that match the web page at `origin`.
#[derive(Clone, PartialEq, Message)]
pub struct BridgeFind {
    /// The page's origin, as the browser reports it (`scheme://host[:port]`).
    #[prost(string, tag = "1")]
    pub origin: String,
    /// The origin of the tab's top frame, if the page is a frame of another
    /// page; empty for a top frame.
    #[prost(string, tag = "2")]
    pub top_origin: String,
}

/// The user name and password of one login, to fill into the page at
/// `origin`, which the login must match.
#[derive(Clone, PartialEq, Message)]
pub struct BridgeFill {
    /// The page's origin.
    #[prost(string, tag = "1")]
    pub origin: String,
    /// The login (16 bytes).
    #[prost(bytes = "vec", tag = "2")]
    pub item_id: Vec<u8>,
    /// The origin of the tab's top frame; empty for a top frame.
    #[prost(string, tag = "3")]
    pub top_origin: String,
}

/// Answer to [`BridgeFind`]: the best matches first. No secrets.
#[derive(Clone, PartialEq, Message)]
pub struct BridgeLogins {
    /// The matching logins.
    #[prost(message, repeated, tag = "1")]
    pub logins: Vec<BridgeLogin>,
}

/// A login that matches a page.
#[derive(Clone, PartialEq, Message)]
pub struct BridgeLogin {
    /// The login (16 bytes).
    #[prost(bytes = "vec", tag = "1")]
    pub item_id: Vec<u8>,
    /// Its title.
    #[prost(string, tag = "2")]
    pub title: String,
    /// Its user name.
    #[prost(string, tag = "3")]
    pub username: String,
    /// Whether it matches the page's host exactly (rather than its site).
    #[prost(bool, tag = "4")]
    pub exact: bool,
}

/// Answer to [`BridgeFill`].
#[derive(Clone, PartialEq, Message, Zeroize, ZeroizeOnDrop)]
#[prost(skip_debug)]
pub struct BridgeCredential {
    /// The user name.
    #[prost(string, tag = "1")]
    pub username: String,
    /// The password.
    #[prost(string, tag = "2")]
    pub password: String,
}

/// The one-time code for a login of the page (`docs/spec/extension.md` §9).
#[derive(Clone, PartialEq, Message)]
pub struct BridgeTotp {
    /// The page's origin.
    #[prost(string, tag = "1")]
    pub origin: String,
    /// The origin of the tab's top frame; empty for a top frame.
    #[prost(string, tag = "2")]
    pub top_origin: String,
    /// The login (16 bytes) the TOTP entry is tied to.
    #[prost(bytes = "vec", tag = "3")]
    pub item_id: Vec<u8>,
}

/// A new login for the page (`docs/spec/extension.md` §8).
#[derive(Clone, PartialEq, Message, Zeroize, ZeroizeOnDrop)]
#[prost(skip_debug)]
pub struct BridgeSave {
    /// The page's origin; the login is saved with it.
    #[prost(string, tag = "1")]
    pub origin: String,
    /// The origin of the tab's top frame; empty for a top frame.
    #[prost(string, tag = "2")]
    pub top_origin: String,
    /// The login's title.
    #[prost(string, tag = "3")]
    pub title: String,
    /// The user name typed into the page.
    #[prost(string, tag = "4")]
    pub username: String,
    /// The password typed into the page.
    #[prost(string, tag = "5")]
    pub password: String,
}

/// A new password for a login of the page.
#[derive(Clone, PartialEq, Message, Zeroize, ZeroizeOnDrop)]
#[prost(skip_debug)]
pub struct BridgeUpdate {
    /// The page's origin.
    #[prost(string, tag = "1")]
    pub origin: String,
    /// The origin of the tab's top frame; empty for a top frame.
    #[prost(string, tag = "2")]
    pub top_origin: String,
    /// The login (16 bytes); it must belong to the page.
    #[prost(bytes = "vec", tag = "3")]
    pub item_id: Vec<u8>,
    /// The new password.
    #[prost(string, tag = "4")]
    pub password: String,
}

/// What the user typed into the page, to compare with the vault.
#[derive(Clone, PartialEq, Message, Zeroize, ZeroizeOnDrop)]
#[prost(skip_debug)]
pub struct BridgeCompare {
    /// The page's origin.
    #[prost(string, tag = "1")]
    pub origin: String,
    /// The origin of the tab's top frame; empty for a top frame.
    #[prost(string, tag = "2")]
    pub top_origin: String,
    /// The user name typed.
    #[prost(string, tag = "3")]
    pub username: String,
    /// The password typed.
    #[prost(string, tag = "4")]
    pub password: String,
}

/// Answer to [`BridgeCompare`].
#[derive(Clone, PartialEq, Message)]
pub struct BridgeComparison {
    /// The login of the page with that user name (16 bytes), compared
    /// regardless of case; empty if there is none, or if no user name was
    /// typed.
    #[prost(bytes = "vec", tag = "1")]
    pub item_id: Vec<u8>,
    /// Whether there is nothing to offer: a login of the page already has
    /// that user name and password; or no user name was typed and the page
    /// has a login with that password, or has logins and it cannot be told
    /// which one changed.
    #[prost(bool, tag = "2")]
    pub same: bool,
}

// ---------------------------------------------------------------------------
// Encrypted export (`docs/spec/export.md`)
// ---------------------------------------------------------------------------

/// Makes an encrypted export of every item of every domain. Every domain
/// must be unlocked.
#[derive(Clone, PartialEq, Message, Zeroize, ZeroizeOnDrop)]
#[prost(skip_debug)]
pub struct ExportVault {
    /// The passphrase that protects the file (at least 12 characters).
    #[prost(string, tag = "1")]
    pub passphrase: String,
}

/// Adds the items of an encrypted export, as new items.
#[derive(Clone, PartialEq, Message, Zeroize, ZeroizeOnDrop)]
#[prost(skip_debug)]
pub struct ImportExport {
    /// The export file.
    #[prost(bytes = "vec", tag = "1")]
    pub data: Vec<u8>,
    /// Its passphrase.
    #[prost(string, tag = "2")]
    pub passphrase: String,
}

/// Answer to [`ExportVault`]: the file, sealed.
#[derive(Clone, PartialEq, Message)]
pub struct Exported {
    /// The export file, ready to be written.
    #[prost(bytes = "vec", tag = "1")]
    pub data: Vec<u8>,
    /// What it holds.
    #[prost(message, optional, tag = "2")]
    pub counts: Option<ItemCounts>,
}

/// Answer to [`ImportExport`].
#[derive(Clone, Copy, PartialEq, Message)]
pub struct ImportedItems {
    /// What was added.
    #[prost(message, optional, tag = "1")]
    pub counts: Option<ItemCounts>,
}

/// How many items of each kind.
#[derive(Clone, Copy, PartialEq, Message)]
pub struct ItemCounts {
    /// Logins.
    #[prost(uint32, tag = "1")]
    pub logins: u32,
    /// Secure notes.
    #[prost(uint32, tag = "2")]
    pub notes: u32,
    /// TOTP entries.
    #[prost(uint32, tag = "3")]
    pub totp: u32,
    /// Passkeys.
    #[prost(uint32, tag = "4")]
    pub passkeys: u32,
}

// ---------------------------------------------------------------------------
// Passkeys (`docs/spec/passkey.md` §9)
// ---------------------------------------------------------------------------

/// Makes a passkey for a web page and keeps it in the vault: what
/// `navigator.credentials.create` asks. Nothing in it is secret.
#[derive(Clone, PartialEq, Message)]
pub struct PasskeyCreate {
    /// The page's origin, as the browser reported it.
    #[prost(string, tag = "1")]
    pub origin: String,
    /// The origin of the tab's top frame; empty for a top frame.
    #[prost(string, tag = "2")]
    pub top_origin: String,
    /// `rp.id`; empty for the page's host.
    #[prost(string, tag = "3")]
    pub rp_id: String,
    /// `rp.name`.
    #[prost(string, tag = "4")]
    pub rp_name: String,
    /// `user.id`: the user handle, 1 to 64 bytes.
    #[prost(bytes = "vec", tag = "5")]
    pub user_handle: Vec<u8>,
    /// `user.name`.
    #[prost(string, tag = "6")]
    pub user_name: String,
    /// `user.displayName`.
    #[prost(string, tag = "7")]
    pub user_display_name: String,
    /// `challenge`.
    #[prost(bytes = "vec", tag = "8")]
    pub challenge: Vec<u8>,
    /// The COSE algorithms of `pubKeyCredParams`, most preferred first.
    #[prost(sint32, repeated, tag = "9")]
    pub algorithms: Vec<i32>,
    /// The credential identifiers of `excludeCredentials`.
    #[prost(bytes = "vec", repeated, tag = "10")]
    pub exclude: Vec<Vec<u8>>,
}

/// Signs for a web page with one of its passkeys: what
/// `navigator.credentials.get` asks. Nothing in it is secret.
#[derive(Clone, PartialEq, Message)]
pub struct PasskeyGet {
    /// The page's origin, as the browser reported it.
    #[prost(string, tag = "1")]
    pub origin: String,
    /// The origin of the tab's top frame; empty for a top frame.
    #[prost(string, tag = "2")]
    pub top_origin: String,
    /// `rpId`; empty for the page's host.
    #[prost(string, tag = "3")]
    pub rp_id: String,
    /// `challenge`.
    #[prost(bytes = "vec", tag = "4")]
    pub challenge: Vec<u8>,
    /// The credential identifiers of `allowCredentials`; empty for any
    /// passkey of the relying party.
    #[prost(bytes = "vec", repeated, tag = "5")]
    pub allow: Vec<Vec<u8>>,
    /// The passkey the user picked among the [`PasskeyChoices`] of the same
    /// request; empty if none.
    #[prost(bytes = "vec", tag = "6")]
    pub chosen: Vec<u8>,
}

/// Answer to [`PasskeyCreate`]: what the relying party receives. Never the
/// private key.
#[derive(Clone, PartialEq, Message)]
pub struct PasskeyCreated {
    /// The credential identifier.
    #[prost(bytes = "vec", tag = "1")]
    pub credential_id: Vec<u8>,
    /// The client data JSON.
    #[prost(bytes = "vec", tag = "2")]
    pub client_data_json: Vec<u8>,
    /// The attestation object ("none" attestation).
    #[prost(bytes = "vec", tag = "3")]
    pub attestation_object: Vec<u8>,
    /// The authenticator data, also inside the attestation object.
    #[prost(bytes = "vec", tag = "4")]
    pub authenticator_data: Vec<u8>,
    /// The public key, DER SubjectPublicKeyInfo.
    #[prost(bytes = "vec", tag = "5")]
    pub public_key: Vec<u8>,
    /// The COSE algorithm of the key.
    #[prost(sint32, tag = "6")]
    pub algorithm: i32,
}

/// Answer to [`PasskeyGet`]: the assertion the relying party receives.
#[derive(Clone, PartialEq, Message)]
pub struct PasskeyAssertion {
    /// The credential that signed.
    #[prost(bytes = "vec", tag = "1")]
    pub credential_id: Vec<u8>,
    /// The client data JSON.
    #[prost(bytes = "vec", tag = "2")]
    pub client_data_json: Vec<u8>,
    /// The authenticator data.
    #[prost(bytes = "vec", tag = "3")]
    pub authenticator_data: Vec<u8>,
    /// The signature over the authenticator data and the client data hash.
    #[prost(bytes = "vec", tag = "4")]
    pub signature: Vec<u8>,
    /// The credential's user handle.
    #[prost(bytes = "vec", tag = "5")]
    pub user_handle: Vec<u8>,
}

/// Answer to [`PasskeyGet`] when several passkeys of the relying party fit:
/// the user picks one, and the same request comes again with it.
#[derive(Clone, PartialEq, Message)]
pub struct PasskeyChoices {
    /// The passkeys, by account name.
    #[prost(message, repeated, tag = "1")]
    pub choices: Vec<PasskeyChoice>,
}

/// A passkey the user may pick.
#[derive(Clone, PartialEq, Message)]
pub struct PasskeyChoice {
    /// The credential identifier.
    #[prost(bytes = "vec", tag = "1")]
    pub credential_id: Vec<u8>,
    /// The account name.
    #[prost(string, tag = "2")]
    pub user_name: String,
    /// The display name.
    #[prost(string, tag = "3")]
    pub user_display_name: String,
}

redacted_debug!(
    PairJoin,
    PairReceiveKeys,
    PairOffered,
    SyncIdentityReply,
    CreateVault,
    RecoverVault,
    Unlock,
    ChangeMasterPassword,
    NewTotp,
    Login,
    Note,
    TotpCodeReply,
    BridgeCredential,
    BridgeSave,
    BridgeUpdate,
    BridgeCompare,
    ExportVault,
    ImportExport,
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
        // A request with only a field this version does not define (tag 120).
        let bytes = [0xC2, 0x07, 0x00];
        assert_eq!(Request::decode(bytes.as_slice()).unwrap().body, None);
    }
}

//! UniFFI bindings exposing the ZeroPass core to the Android app.
//!
//! The app has two processes (ADR-0012, `docs/spec/android.md`):
//!
//! - the **vault process**, an `isolatedProcess` service without permissions,
//!   files or network, runs the vault daemon ([`serve_vault_connection`]);
//! - the **app process** reaches it over socket pairs ([`VaultClient`]),
//!   stores the vault file for it, answers for the hardware key store
//!   ([`PlatformKeyStore`]) and holds the connections to the other devices:
//!   the app moves the bytes over its radio ([`ByteLink`]), the core runs
//!   pairing, the Noise channel and sync, the same code as on the desktop.
//!
//! Every function blocks until it is done; call them off the UI thread.

mod client;
mod engine;
mod error;
mod link;
mod nearby;
mod pages;

pub use client::{
    DeviceInfo, DeviceState, DomainState, HardwareError, ItemContent, ItemKind, ItemList,
    ItemSummary, PlatformKeyStore, TotpCode, VaultClient, VaultConnector, VaultStatus,
};
pub use engine::serve_vault_connection;
pub use error::{Problem, ZpError};
pub use link::{ByteLink, LinkError};
pub use nearby::{
    BleUuids, JoinOutcome, LanSync, OfferInfo, Peer, SyncOutcome, announces_pairing, ble_uuids,
    offer_info, to_hex,
};
pub use pages::{
    PageComparison, PageCredential, PageLogin, PasskeyChoice, PasskeyCreation, PasskeyMade,
    PasskeyRequest, PasskeySignature,
};

use zp_ipc::proto;

uniffi::setup_scaffolding!();

/// A key domain of the vault (`docs/spec/crypto.md` §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum Domain {
    /// Logins and secure notes: the master password unlocks it.
    Password,
    /// One-time codes: the hardware key store unlocks it.
    Totp,
    /// Passkeys: the hardware key store unlocks it.
    Passkey,
}

impl Domain {
    pub(crate) fn from_proto(value: i32) -> Option<Self> {
        match proto::Domain::try_from(value) {
            Ok(proto::Domain::Password) => Some(Self::Password),
            Ok(proto::Domain::Totp) => Some(Self::Totp),
            Ok(proto::Domain::Passkey) => Some(Self::Passkey),
            _ => None,
        }
    }

    pub(crate) fn to_proto(self) -> proto::Domain {
        match self {
            Self::Password => proto::Domain::Password,
            Self::Totp => proto::Domain::Totp,
            Self::Passkey => proto::Domain::Passkey,
        }
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) fn parse_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let text = text.trim();
    if text.len() != 2 * N || !text.is_ascii() {
        return None;
    }
    let mut bytes = [0u8; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * index..2 * index + 2], 16).ok()?;
    }
    Some(bytes)
}

#[cfg(test)]
mod tests;

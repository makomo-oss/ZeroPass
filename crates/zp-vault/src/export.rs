//! Encrypted export and its import (`docs/spec/export.md`).
//!
//! An export holds every item of every domain of the vault, TOTP seeds and
//! passkey keys included, sealed under a key derived from a passphrase the
//! user chooses for the file. It is made and read only where every vault key
//! is at hand (in the daemon's short-lived process for the whole vault):
//! nothing outside it ever sees the items in the clear.
//!
//! ```text
//! file   = header ‖ envelope
//! header = "ZPEXPORT" ‖ version (1) ‖ m (u32) ‖ t (u32) ‖ p (u32) ‖ salt (16)
//! key    = HKDF-SHA256(salt, Argon2id(NFKC(passphrase), salt, m, t, p), "zeropass/v1/export")
//! envelope = crypto.md §4, associated data = header
//! plaintext = ExportArchive (Protocol Buffers)
//! ```

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use prost::Message;
use zeroize::Zeroizing;
use zp_crypto::{
    CryptoError, Domain, DomainId, ExportKey, ItemId, KDF_SALT_LEN, KdfParams, Passkey, Password,
    Totp,
};

use crate::model::{Content, Login, PasskeyCredential, SecureNote, TotpEntry};
use crate::{MIN_MASTER_PASSWORD_CHARS, Vault, VaultError};

/// The first bytes of an export file.
pub const MAGIC: &[u8; 8] = b"ZPEXPORT";
/// The version of the format this code writes and reads.
pub const FORMAT_VERSION: u8 = 1;
const HEADER_LEN: usize = MAGIC.len() + 1 + 3 * 4 + KDF_SALT_LEN;

/// What can go wrong with an export file.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    /// The file does not start like an export.
    #[error("the file is not a ZeroPass export")]
    NotAnExport,
    /// A version of the format this code does not know.
    #[error("export format version {0} is not supported")]
    UnsupportedVersion(u8),
    /// The passphrase does not open the file, or the file was changed.
    #[error("the passphrase is wrong, or the file was changed")]
    WrongPassphrase,
    /// The passphrase is too short to protect a whole vault.
    #[error("the passphrase must be at least {MIN_MASTER_PASSWORD_CHARS} characters long")]
    WeakPassphrase,
    /// The opened file holds no valid archive.
    #[error("the export file is damaged")]
    Damaged,
    /// The vault refused (a locked domain, ...).
    #[error(transparent)]
    Vault(#[from] VaultError),
    /// Key derivation or encryption failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// How many items of each kind an export or import held.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ExportSummary {
    /// Logins.
    pub logins: usize,
    /// Secure notes.
    pub notes: usize,
    /// TOTP entries.
    pub totp: usize,
    /// Passkeys.
    pub passkeys: usize,
}

impl ExportSummary {
    /// Every item.
    pub fn total(&self) -> usize {
        self.logins + self.notes + self.totp + self.passkeys
    }
}

/// The contents of an export.
#[derive(Clone, PartialEq, Message)]
struct ExportArchive {
    /// The vault it came from.
    #[prost(bytes = "vec", tag = "1")]
    vault_id: Vec<u8>,
    /// When it was made, milliseconds since the UNIX epoch.
    #[prost(uint64, tag = "2")]
    created_ms: u64,
    #[prost(message, repeated, tag = "3")]
    items: Vec<ExportedItem>,
}

/// One item: its identifier in the vault it came from (for the links of
/// TOTP entries to logins), and exactly one content.
#[derive(Clone, PartialEq, Message)]
struct ExportedItem {
    #[prost(bytes = "vec", tag = "1")]
    item_id: Vec<u8>,
    #[prost(message, optional, tag = "2")]
    login: Option<Login>,
    #[prost(message, optional, tag = "3")]
    note: Option<SecureNote>,
    #[prost(message, optional, tag = "4")]
    totp: Option<TotpEntry>,
    #[prost(message, optional, tag = "5")]
    passkey: Option<PasskeyCredential>,
}

fn header(params: &KdfParams, salt: &[u8; KDF_SALT_LEN]) -> Vec<u8> {
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.push(FORMAT_VERSION);
    header.extend_from_slice(&params.m_kib().to_be_bytes());
    header.extend_from_slice(&params.t().to_be_bytes());
    header.extend_from_slice(&params.p().to_be_bytes());
    header.extend_from_slice(salt);
    header
}

fn check_passphrase(passphrase: &str) -> Result<(), ExportError> {
    if passphrase.chars().count() < MIN_MASTER_PASSWORD_CHARS {
        return Err(ExportError::WeakPassphrase);
    }
    Ok(())
}

impl Vault {
    fn exported<D: Domain>(
        &mut self,
        items: &mut Vec<ExportedItem>,
        summary: &mut ExportSummary,
    ) -> Result<(), VaultError> {
        if !self.has_domain(D::ID)? {
            return Ok(());
        }
        for (id, content) in self.list::<D>()? {
            let mut item = ExportedItem {
                item_id: id.as_bytes().to_vec(),
                ..ExportedItem::default()
            };
            match content {
                Content::Login(login) => {
                    summary.logins += 1;
                    item.login = Some(login);
                }
                Content::SecureNote(note) => {
                    summary.notes += 1;
                    item.note = Some(note);
                }
                Content::Totp(entry) => {
                    summary.totp += 1;
                    item.totp = Some(entry);
                }
                Content::Passkey(passkey) => {
                    summary.passkeys += 1;
                    item.passkey = Some(passkey);
                }
            }
            items.push(item);
        }
        Ok(())
    }

    /// Makes an encrypted export of every item of every domain the vault
    /// has; each must be unlocked. `params` sets the cost of guessing the
    /// passphrase.
    pub fn export_encrypted(
        &mut self,
        passphrase: &str,
        params: &KdfParams,
    ) -> Result<(Vec<u8>, ExportSummary), ExportError> {
        check_passphrase(passphrase)?;
        for domain in DomainId::ALL {
            if self.has_domain(domain)? && !self.is_unlocked(domain) {
                return Err(VaultError::Locked(domain).into());
            }
        }
        let mut summary = ExportSummary::default();
        let mut items = Vec::new();
        self.exported::<Password>(&mut items, &mut summary)?;
        self.exported::<Totp>(&mut items, &mut summary)?;
        self.exported::<Passkey>(&mut items, &mut summary)?;
        let archive = ExportArchive {
            vault_id: self.vault_id().as_bytes().to_vec(),
            created_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| {
                    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
                }),
            items,
        };
        let plaintext = Zeroizing::new(archive.encode_to_vec());
        let salt: [u8; KDF_SALT_LEN] = zp_crypto::rng::array()?;
        let header = header(params, &salt);
        let key = ExportKey::derive(passphrase, &salt, params)?;
        let mut file = header.clone();
        file.extend_from_slice(&key.seal(&header, &plaintext)?);
        Ok((file, summary))
    }

    /// Adds the items of an encrypted export to this vault, as new items.
    /// Every domain the file holds items of must be unlocked. TOTP entries
    /// stay tied to the logins they were tied to.
    pub fn import_encrypted(
        &mut self,
        file: &[u8],
        passphrase: &str,
    ) -> Result<ExportSummary, ExportError> {
        if file.len() < HEADER_LEN || &file[..MAGIC.len()] != MAGIC {
            return Err(ExportError::NotAnExport);
        }
        let version = file[MAGIC.len()];
        if version != FORMAT_VERSION {
            return Err(ExportError::UnsupportedVersion(version));
        }
        let word = |at: usize| {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&file[at..at + 4]);
            u32::from_be_bytes(bytes)
        };
        let base = MAGIC.len() + 1;
        // Read-time ceilings apply: a forged file cannot exhaust memory.
        let params = KdfParams::new(word(base), word(base + 4), word(base + 8))
            .map_err(|_| ExportError::Damaged)?;
        let mut salt = [0u8; KDF_SALT_LEN];
        salt.copy_from_slice(&file[base + 12..HEADER_LEN]);
        let (header, sealed) = file.split_at(HEADER_LEN);
        let key = ExportKey::derive(passphrase, &salt, &params)?;
        let plaintext = key
            .open(header, sealed)
            .map_err(|_| ExportError::WrongPassphrase)?;
        let archive =
            ExportArchive::decode(plaintext.as_slice()).map_err(|_| ExportError::Damaged)?;

        // Everything is checked before anything is written.
        let mut needed = Vec::new();
        for item in &archive.items {
            let domain = if item.totp.is_some() {
                DomainId::Totp
            } else if item.passkey.is_some() {
                DomainId::Passkey
            } else {
                DomainId::Password
            };
            if !needed.contains(&domain) {
                needed.push(domain);
            }
        }
        for domain in needed {
            if !self.has_domain(domain)? {
                return Err(VaultError::DomainUnavailable(domain).into());
            }
            if !self.is_unlocked(domain) {
                return Err(VaultError::Locked(domain).into());
            }
        }

        let mut summary = ExportSummary::default();
        let mut new_ids: HashMap<Vec<u8>, ItemId> = HashMap::new();
        let mut later = Vec::new();
        for item in archive.items {
            if let Some(login) = item.login {
                new_ids.insert(item.item_id, self.insert(login)?);
                summary.logins += 1;
            } else if let Some(note) = item.note {
                new_ids.insert(item.item_id, self.insert(note)?);
                summary.notes += 1;
            } else {
                later.push(item);
            }
        }
        for item in later {
            if let Some(mut entry) = item.totp {
                entry.login_item_id = new_ids
                    .get(&entry.login_item_id)
                    .map(|id| id.as_bytes().to_vec())
                    .unwrap_or_default();
                self.insert(entry)?;
                summary.totp += 1;
            } else if let Some(passkey) = item.passkey {
                self.insert(passkey)?;
                summary.passkeys += 1;
            }
        }
        Ok(summary)
    }
}

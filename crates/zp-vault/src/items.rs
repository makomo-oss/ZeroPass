//! Encrypted item storage (`docs/spec/crypto.md` §9).
//!
//! Every write creates a new version of an item with a fresh item key:
//!
//! ```text
//! ciphertext  = seal(DEK,  AAD_item, protobuf(content))
//! wrapped_dek = seal(VK-D, AAD_dek,  DEK)
//! ```
//!
//! The previous version moves to the history table, and deletion is recorded as a
//! tombstone version without payload. Callers pass the vault key of the item's
//! domain for the duration of each call; this module never stores it.

use rusqlite::{OptionalExtension, Row, params};
use zp_crypto::{DeviceId, Domain, DomainId, ItemContext, ItemId, ItemKey, VaultKey};

use crate::model::{Content, Item};
use crate::{Store, VaultError};

/// One stored version of an item, exactly as it is on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ItemRow {
    pub(crate) item_id: ItemId,
    pub(crate) domain: DomainId,
    pub(crate) hlc: u64,
    pub(crate) device_id: DeviceId,
    /// `None` for a tombstone.
    pub(crate) payload: Option<Payload>,
}

/// The encrypted part of a live item version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Payload {
    pub(crate) wrapped_dek: Vec<u8>,
    pub(crate) ciphertext: Vec<u8>,
}

/// A superseded version of an item.
#[derive(Debug, Clone, PartialEq)]
pub struct HistoryEntry {
    /// Clock stamp of the version.
    pub hlc: u64,
    /// The device that wrote it.
    pub device_id: DeviceId,
    /// The content, or `None` if this version was a deletion.
    pub content: Option<Content>,
}

const COLUMNS: &str = "item_id, domain, hlc, device_id, deleted, wrapped_dek, ciphertext";

fn corrupt(_: impl Sized) -> VaultError {
    VaultError::Corrupt("malformed item row")
}

fn read_row(row: &Row<'_>) -> Result<Result<ItemRow, VaultError>, rusqlite::Error> {
    let item_id: Vec<u8> = row.get(0)?;
    let domain: u8 = row.get(1)?;
    let hlc: i64 = row.get(2)?;
    let device_id: Vec<u8> = row.get(3)?;
    let deleted: bool = row.get(4)?;
    let wrapped_dek: Option<Vec<u8>> = row.get(5)?;
    let ciphertext: Option<Vec<u8>> = row.get(6)?;

    Ok((|| {
        let payload = match (deleted, wrapped_dek, ciphertext) {
            (true, None, None) => None,
            (false, Some(wrapped_dek), Some(ciphertext)) => Some(Payload {
                wrapped_dek,
                ciphertext,
            }),
            _ => return Err(corrupt(())),
        };
        Ok(ItemRow {
            item_id: ItemId::from_slice(&item_id).ok_or_else(|| corrupt(()))?,
            domain: DomainId::from_u8(domain).ok_or_else(|| corrupt(()))?,
            hlc: u64::try_from(hlc).map_err(corrupt)?,
            device_id: DeviceId::from_slice(&device_id).ok_or_else(|| corrupt(()))?,
            payload,
        })
    })())
}

impl Store {
    fn context(&self, row: &ItemRow) -> ItemContext {
        ItemContext {
            vault_id: self.vault_id(),
            item_id: row.item_id,
            hlc: row.hlc,
            device_id: row.device_id,
        }
    }

    /// Reads the current version of an item, tombstones included.
    pub(crate) fn current_row(&self, item_id: ItemId) -> Result<Option<ItemRow>, VaultError> {
        self.conn
            .query_row(
                &format!("SELECT {COLUMNS} FROM items WHERE item_id = ?1"),
                params![item_id.as_bytes()],
                read_row,
            )
            .optional()?
            .transpose()
    }

    /// Makes `row` the current version of its item, moving the version it replaces
    /// (if any) to the history. Both happen in one transaction.
    pub(crate) fn write_row(&mut self, row: &ItemRow) -> Result<(), VaultError> {
        self.write_rows(std::slice::from_ref(row))
    }

    /// Writes several item versions in a single transaction: either all of them
    /// become current, or none.
    pub(crate) fn write_rows(&mut self, rows: &[ItemRow]) -> Result<(), VaultError> {
        let tx = self.conn.transaction()?;
        {
            let mut archive = tx.prepare(&format!(
                "INSERT OR IGNORE INTO item_history ({COLUMNS})
                 SELECT {COLUMNS} FROM items WHERE item_id = ?1"
            ))?;
            let mut upsert = tx.prepare(&format!(
                "INSERT INTO items ({COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT (item_id) DO UPDATE SET
                     domain = excluded.domain,
                     hlc = excluded.hlc,
                     device_id = excluded.device_id,
                     deleted = excluded.deleted,
                     wrapped_dek = excluded.wrapped_dek,
                     ciphertext = excluded.ciphertext"
            ))?;
            for row in rows {
                let hlc = i64::try_from(row.hlc).map_err(|_| VaultError::ClockExhausted)?;
                let (wrapped_dek, ciphertext) = match &row.payload {
                    Some(payload) => (Some(&payload.wrapped_dek), Some(&payload.ciphertext)),
                    None => (None, None),
                };
                archive.execute(params![row.item_id.as_bytes()])?;
                upsert.execute(params![
                    row.item_id.as_bytes(),
                    row.domain.as_u8(),
                    hlc,
                    row.device_id.as_bytes(),
                    row.payload.is_none(),
                    wrapped_dek,
                    ciphertext,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Encrypts `content` as a new version of `item_id`.
    fn seal_version<D: Domain>(
        &mut self,
        key: &VaultKey<D>,
        item_id: ItemId,
        content: &Content,
    ) -> Result<ItemRow, VaultError> {
        debug_assert_eq!(content.kind().domain(), D::ID);
        let mut row = ItemRow {
            item_id,
            domain: D::ID,
            hlc: self.next_hlc()?,
            device_id: self.device_id(),
            payload: None,
        };
        let ctx = self.context(&row);
        let dek = ItemKey::<D>::generate()?;
        row.payload = Some(Payload {
            ciphertext: dek.seal_item(&ctx, &content.to_plaintext())?,
            wrapped_dek: key.wrap_item_key(&dek, &ctx)?,
        });
        Ok(row)
    }

    /// Decrypts a stored version. Returns `None` for a tombstone.
    fn open_version<D: Domain>(
        &self,
        key: &VaultKey<D>,
        row: &ItemRow,
    ) -> Result<Option<Content>, VaultError> {
        if row.domain != D::ID {
            return Err(VaultError::DomainMismatch);
        }
        let Some(payload) = &row.payload else {
            return Ok(None);
        };
        let ctx = self.context(row);
        let dek = key.unwrap_item_key(&ctx, &payload.wrapped_dek)?;
        let plaintext = dek.open_item(&ctx, &payload.ciphertext)?;
        Content::from_plaintext(&plaintext, row.domain).map(Some)
    }

    /// Stores a new item and returns its identifier.
    pub fn insert_item<I: Item>(
        &mut self,
        key: &VaultKey<I::Domain>,
        item: I,
    ) -> Result<ItemId, VaultError> {
        let item_id = ItemId::generate()?;
        let row = self.seal_version(key, item_id, &item.into_content())?;
        self.write_row(&row)?;
        Ok(item_id)
    }

    /// Stores several new items of one kind atomically and returns their
    /// identifiers in order. Much faster than repeated [`Self::insert_item`] calls,
    /// which each wait for the disk.
    pub fn insert_items<I: Item>(
        &mut self,
        key: &VaultKey<I::Domain>,
        items: impl IntoIterator<Item = I>,
    ) -> Result<Vec<ItemId>, VaultError> {
        let mut rows = Vec::new();
        for item in items {
            let item_id = ItemId::generate()?;
            rows.push(self.seal_version(key, item_id, &item.into_content())?);
        }
        self.write_rows(&rows)?;
        Ok(rows.iter().map(|row| row.item_id).collect())
    }

    /// Replaces the content of an existing item. The previous version is kept in
    /// the history.
    ///
    /// Fails with [`VaultError::ItemNotFound`] if the item does not exist or was
    /// deleted, and with [`VaultError::DomainMismatch`] if it belongs to another
    /// domain: an item never changes domain.
    pub fn update_item<I: Item>(
        &mut self,
        key: &VaultKey<I::Domain>,
        item_id: ItemId,
        item: I,
    ) -> Result<(), VaultError> {
        let current = self.live_row(item_id)?;
        if current.domain != I::Domain::ID {
            return Err(VaultError::DomainMismatch);
        }
        let row = self.seal_version(key, item_id, &item.into_content())?;
        self.write_row(&row)
    }

    fn live_row(&self, item_id: ItemId) -> Result<ItemRow, VaultError> {
        self.current_row(item_id)?
            .filter(|row| row.payload.is_some())
            .ok_or(VaultError::ItemNotFound)
    }

    /// Reads and decrypts an item of kind `I`.
    pub fn get_item<I: Item>(
        &self,
        key: &VaultKey<I::Domain>,
        item_id: ItemId,
    ) -> Result<I, VaultError> {
        let content = self.get_content(key, item_id)?;
        I::from_content(content).ok_or(VaultError::WrongItemKind)
    }

    /// Reads and decrypts an item of any kind stored in domain `D`.
    pub fn get_content<D: Domain>(
        &self,
        key: &VaultKey<D>,
        item_id: ItemId,
    ) -> Result<Content, VaultError> {
        let row = self.live_row(item_id)?;
        self.open_version(key, &row)?
            .ok_or(VaultError::ItemNotFound)
    }

    /// Decrypts every live item of domain `D`.
    pub fn list_items<D: Domain>(
        &self,
        key: &VaultKey<D>,
    ) -> Result<Vec<(ItemId, Content)>, VaultError> {
        let mut statement = self.conn.prepare(&format!(
            "SELECT {COLUMNS} FROM items WHERE domain = ?1 AND deleted = 0 ORDER BY item_id"
        ))?;
        let rows = statement.query_map(params![D::ID.as_u8()], read_row)?;

        let mut items = Vec::new();
        for row in rows {
            let row = row??;
            let content = self.open_version(key, &row)?.ok_or_else(|| corrupt(()))?;
            items.push((row.item_id, content));
        }
        Ok(items)
    }

    /// Decrypts the live items of domain `D` and returns those matching `query`
    /// (see [`Content::matches`]). Matching happens in memory after decryption;
    /// nothing searchable is stored in the clear.
    pub fn search_items<D: Domain>(
        &self,
        key: &VaultKey<D>,
        query: &str,
    ) -> Result<Vec<(ItemId, Content)>, VaultError> {
        let mut items = self.list_items(key)?;
        items.retain(|(_, content)| content.matches(query));
        Ok(items)
    }

    /// Deletes an item by recording a tombstone version. The deleted content stays
    /// in the history. No key is needed, but the caller names the domain so that a
    /// component holding only one domain cannot delete another domain's items.
    pub fn delete_item<D: Domain>(&mut self, item_id: ItemId) -> Result<(), VaultError> {
        let current = self.live_row(item_id)?;
        if current.domain != D::ID {
            return Err(VaultError::DomainMismatch);
        }
        let tombstone = ItemRow {
            item_id,
            domain: D::ID,
            hlc: self.next_hlc()?,
            device_id: self.device_id(),
            payload: None,
        };
        self.write_row(&tombstone)
    }

    /// The superseded versions of an item, newest first. The current version is
    /// not included.
    pub fn item_history<D: Domain>(
        &self,
        key: &VaultKey<D>,
        item_id: ItemId,
    ) -> Result<Vec<HistoryEntry>, VaultError> {
        let mut statement = self.conn.prepare(&format!(
            "SELECT {COLUMNS} FROM item_history WHERE item_id = ?1 ORDER BY hlc DESC, device_id"
        ))?;
        let rows = statement.query_map(params![item_id.as_bytes()], read_row)?;

        let mut history = Vec::new();
        for row in rows {
            let row = row??;
            history.push(HistoryEntry {
                hlc: row.hlc,
                device_id: row.device_id,
                content: self.open_version(key, &row)?,
            });
        }
        Ok(history)
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use zp_crypto::{CryptoError, Passkey, Password, Totp};

    use super::*;
    use crate::clock::Clock;
    use crate::model::{Login, PasskeyCredential, SecureNote, TotpEntry};

    struct Fixture {
        _dir: tempfile::TempDir,
        path: std::path::PathBuf,
        store: Store,
        vk_p: VaultKey<Password>,
        vk_t: VaultKey<Totp>,
        vk_k: VaultKey<Passkey>,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.zpvault");
        Fixture {
            store: Store::create(&path).unwrap(),
            path,
            _dir: dir,
            vk_p: VaultKey::generate().unwrap(),
            vk_t: VaultKey::generate().unwrap(),
            vk_k: VaultKey::generate().unwrap(),
        }
    }

    fn login(password: &str) -> Login {
        Login::new("Example", "alice@example.com", password).with_url("https://example.com")
    }

    fn passkey() -> PasskeyCredential {
        PasskeyCredential {
            rp_id: "example.com".into(),
            rp_name: "Example".into(),
            user_handle: vec![1, 2, 3],
            user_name: "alice".into(),
            user_display_name: "Alice".into(),
            credential_id: vec![9; 16],
            private_key: vec![7; 48],
            cose_algorithm: -7,
        }
    }

    fn is_decrypt_error(error: &VaultError) -> bool {
        matches!(error, VaultError::Crypto(CryptoError::Decrypt))
    }

    #[test]
    fn insert_then_get_round_trips_in_every_domain() {
        let mut f = fixture();
        let login_id = f.store.insert_item(&f.vk_p, login("pw-1")).unwrap();
        let note_id = f
            .store
            .insert_item(&f.vk_p, SecureNote::new("Wi-Fi", "secret"))
            .unwrap();
        let totp = TotpEntry::new("Example", "alice", vec![1; 20]).for_login(login_id);
        let totp_id = f.store.insert_item(&f.vk_t, totp.clone()).unwrap();
        let passkey_id = f.store.insert_item(&f.vk_k, passkey()).unwrap();

        assert_eq!(
            f.store.get_item::<Login>(&f.vk_p, login_id).unwrap(),
            login("pw-1")
        );
        assert_eq!(
            f.store.get_item::<SecureNote>(&f.vk_p, note_id).unwrap(),
            SecureNote::new("Wi-Fi", "secret")
        );
        assert_eq!(
            f.store.get_item::<TotpEntry>(&f.vk_t, totp_id).unwrap(),
            totp
        );
        assert_eq!(
            f.store
                .get_item::<PasskeyCredential>(&f.vk_k, passkey_id)
                .unwrap(),
            passkey()
        );
    }

    #[test]
    fn items_survive_reopening_the_file() {
        let mut f = fixture();
        let id = f.store.insert_item(&f.vk_p, login("pw-1")).unwrap();
        drop(f.store);
        let store = Store::open(&f.path).unwrap();
        assert_eq!(store.get_item::<Login>(&f.vk_p, id).unwrap(), login("pw-1"));
    }

    #[test]
    fn get_distinguishes_missing_items_and_wrong_kinds() {
        let mut f = fixture();
        let id = f.store.insert_item(&f.vk_p, login("pw-1")).unwrap();
        assert!(matches!(
            f.store
                .get_item::<Login>(&f.vk_p, ItemId::from_bytes([0; 16])),
            Err(VaultError::ItemNotFound)
        ));
        assert!(matches!(
            f.store.get_item::<SecureNote>(&f.vk_p, id),
            Err(VaultError::WrongItemKind)
        ));
    }

    #[test]
    fn many_items_are_inserted_atomically() {
        let mut f = fixture();
        let logins: Vec<Login> = (0..50).map(|n| login(&format!("pw-{n}"))).collect();
        let ids = f.store.insert_items(&f.vk_p, logins.clone()).unwrap();
        assert_eq!(ids.len(), 50);
        for (id, expected) in ids.iter().zip(&logins) {
            assert_eq!(&f.store.get_item::<Login>(&f.vk_p, *id).unwrap(), expected);
        }
        // Stamps are distinct and increasing in insertion order.
        let stamps: Vec<u64> = ids
            .iter()
            .map(|id| f.store.current_row(*id).unwrap().unwrap().hlc)
            .collect();
        assert!(stamps.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(f.store.list_items(&f.vk_p).unwrap().len(), 50);
        assert!(
            f.store
                .insert_items(&f.vk_p, Vec::<Login>::new())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_failed_batch_writes_nothing() {
        let mut f = fixture();
        let existing = f.store.insert_item(&f.vk_p, login("pw")).unwrap();
        let mut rows = vec![f.store.current_row(existing).unwrap().unwrap()];
        rows[0].item_id = ItemId::from_bytes([1; 16]);
        // A second row that violates the schema (a clock stamp that does not fit).
        let mut invalid = rows[0].clone();
        invalid.item_id = ItemId::from_bytes([2; 16]);
        invalid.hlc = u64::MAX;
        rows.push(invalid);
        assert!(matches!(
            f.store.write_rows(&rows),
            Err(VaultError::ClockExhausted)
        ));
        assert!(
            f.store
                .current_row(ItemId::from_bytes([1; 16]))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn search_matches_visible_fields_only() {
        let mut f = fixture();
        let bank = Login::new("My Bank", "alice@example.com", "secret-bank-pw")
            .with_url("https://bank.example.com/login");
        let bank_id = f.store.insert_item(&f.vk_p, bank).unwrap();
        let note_id = f
            .store
            .insert_item(&f.vk_p, SecureNote::new("Bank PIN", "1234"))
            .unwrap();
        f.store
            .insert_item(&f.vk_p, Login::new("Forum", "bob", "bank"))
            .unwrap();

        let ids = |query: &str| {
            let mut ids: Vec<ItemId> = f
                .store
                .search_items(&f.vk_p, query)
                .unwrap()
                .into_iter()
                .map(|(id, _)| id)
                .collect();
            ids.sort();
            ids
        };
        let mut both = vec![bank_id, note_id];
        both.sort();
        // Case-insensitive, on titles; the forum login only has "bank" as password.
        assert_eq!(ids("BANK"), both);
        assert_eq!(ids("alice@"), [bank_id]);
        assert_eq!(ids("bank.example.com"), [bank_id]);
        assert!(ids("secret-bank-pw").is_empty());
        assert!(ids("1234").is_empty());
        assert_eq!(ids("  ").len(), 3);
        assert!(ids("no such thing").is_empty());
    }

    #[test]
    fn the_wrong_vault_key_cannot_decrypt() {
        let mut f = fixture();
        let id = f.store.insert_item(&f.vk_p, login("pw-1")).unwrap();
        let other = VaultKey::<Password>::generate().unwrap();
        assert!(is_decrypt_error(
            &f.store.get_item::<Login>(&other, id).unwrap_err()
        ));
        assert!(is_decrypt_error(&f.store.list_items(&other).unwrap_err()));
    }

    #[test]
    fn a_domain_key_only_reaches_its_own_domain() {
        let mut f = fixture();
        let totp_id = f
            .store
            .insert_item(&f.vk_t, TotpEntry::new("Example", "a", vec![1; 20]))
            .unwrap();
        // Asking for a TOTP row through the password domain is refused outright.
        assert!(matches!(
            f.store.get_content(&f.vk_p, totp_id),
            Err(VaultError::DomainMismatch)
        ));
        assert!(matches!(
            f.store.delete_item::<Password>(totp_id),
            Err(VaultError::DomainMismatch)
        ));
        assert!(matches!(
            f.store.update_item(&f.vk_p, totp_id, login("pw")),
            Err(VaultError::DomainMismatch)
        ));
        assert!(f.store.list_items(&f.vk_p).unwrap().is_empty());
        assert_eq!(f.store.list_items(&f.vk_t).unwrap().len(), 1);
    }

    #[test]
    fn list_returns_only_live_items_of_the_domain() {
        let mut f = fixture();
        let a = f.store.insert_item(&f.vk_p, login("pw-a")).unwrap();
        let b = f
            .store
            .insert_item(&f.vk_p, SecureNote::new("note", "body"))
            .unwrap();
        let c = f.store.insert_item(&f.vk_p, login("pw-c")).unwrap();
        f.store.insert_item(&f.vk_k, passkey()).unwrap();
        f.store.delete_item::<Password>(c).unwrap();

        let mut ids: Vec<ItemId> = f
            .store
            .list_items(&f.vk_p)
            .unwrap()
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        ids.sort();
        let mut expected = vec![a, b];
        expected.sort();
        assert_eq!(ids, expected);
    }

    #[test]
    fn update_keeps_the_previous_version_in_history() {
        let mut f = fixture();
        let id = f.store.insert_item(&f.vk_p, login("pw-1")).unwrap();
        f.store.update_item(&f.vk_p, id, login("pw-2")).unwrap();
        f.store.update_item(&f.vk_p, id, login("pw-3")).unwrap();

        assert_eq!(
            f.store.get_item::<Login>(&f.vk_p, id).unwrap(),
            login("pw-3")
        );
        let history = f.store.item_history(&f.vk_p, id).unwrap();
        let passwords: Vec<_> = history
            .iter()
            .map(|entry| {
                Login::from_content(entry.content.clone().unwrap())
                    .unwrap()
                    .password
                    .clone()
            })
            .collect();
        assert_eq!(passwords, ["pw-2", "pw-1"]);
        assert!(history[0].hlc > history[1].hlc);
        assert!(
            history
                .iter()
                .all(|entry| entry.device_id == f.store.device_id())
        );
    }

    #[test]
    fn every_version_gets_a_fresh_key_and_stamp() {
        let mut f = fixture();
        let id = f.store.insert_item(&f.vk_p, login("same")).unwrap();
        let first = f.store.current_row(id).unwrap().unwrap();
        f.store.update_item(&f.vk_p, id, login("same")).unwrap();
        let second = f.store.current_row(id).unwrap().unwrap();

        assert!(second.hlc > first.hlc);
        let (first, second) = (first.payload.unwrap(), second.payload.unwrap());
        assert_ne!(first.wrapped_dek, second.wrapped_dek);
        assert_ne!(first.ciphertext, second.ciphertext);
    }

    #[test]
    fn delete_leaves_a_tombstone_and_keeps_history() {
        let mut f = fixture();
        let id = f.store.insert_item(&f.vk_p, login("pw-1")).unwrap();
        f.store.delete_item::<Password>(id).unwrap();

        assert!(matches!(
            f.store.get_item::<Login>(&f.vk_p, id),
            Err(VaultError::ItemNotFound)
        ));
        let tombstone = f.store.current_row(id).unwrap().unwrap();
        assert_eq!(tombstone.payload, None);
        assert_eq!(tombstone.domain, DomainId::Password);

        let history = f.store.item_history(&f.vk_p, id).unwrap();
        assert_eq!(history.len(), 1);
        assert!(history[0].hlc < tombstone.hlc);
        assert_eq!(
            Login::from_content(history[0].content.clone().unwrap()).unwrap(),
            login("pw-1")
        );

        // Deleted items cannot be deleted or updated again.
        assert!(matches!(
            f.store.delete_item::<Password>(id),
            Err(VaultError::ItemNotFound)
        ));
        assert!(matches!(
            f.store.update_item(&f.vk_p, id, login("pw-2")),
            Err(VaultError::ItemNotFound)
        ));
    }

    #[test]
    fn stamps_keep_increasing_across_reopen_even_if_the_clock_goes_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.zpvault");
        let now = Arc::new(AtomicU64::new(2_000_000));
        let source = Arc::clone(&now);
        let clock = Clock::from_fn(move || source.load(Ordering::SeqCst));
        let vk = VaultKey::<Password>::generate().unwrap();

        let mut store = Store::create_with_clock(&path, clock.clone()).unwrap();
        let id = store.insert_item(&vk, login("pw-1")).unwrap();
        let first = store.current_row(id).unwrap().unwrap().hlc;
        assert_eq!(first, 2_000_000 << 16);
        drop(store);

        now.store(1_000_000, Ordering::SeqCst);
        let mut store = Store::open_with_clock(&path, clock).unwrap();
        store.update_item(&vk, id, login("pw-2")).unwrap();
        assert_eq!(store.current_row(id).unwrap().unwrap().hlc, first + 1);
    }

    fn sql(path: &Path, statement: &str) {
        rusqlite::Connection::open(path)
            .unwrap()
            .execute(statement, [])
            .unwrap();
    }

    #[test]
    fn rows_cannot_be_transplanted_between_items() {
        let mut f = fixture();
        let a = f.store.insert_item(&f.vk_p, login("pw-a")).unwrap();
        let b = f.store.insert_item(&f.vk_p, login("pw-b")).unwrap();
        drop(f.store);
        // Overwrite item A's payload with item B's.
        sql(
            &f.path,
            &format!(
                "UPDATE items SET (wrapped_dek, ciphertext) =
                     (SELECT wrapped_dek, ciphertext FROM items WHERE item_id = x'{b}')
                 WHERE item_id = x'{a}'"
            ),
        );
        let store = Store::open(&f.path).unwrap();
        assert!(is_decrypt_error(
            &store.get_item::<Login>(&f.vk_p, a).unwrap_err()
        ));
        assert_eq!(store.get_item::<Login>(&f.vk_p, b).unwrap(), login("pw-b"));
    }

    #[test]
    fn tampered_metadata_is_detected() {
        let mut f = fixture();
        let id = f.store.insert_item(&f.vk_p, login("pw-1")).unwrap();
        drop(f.store);

        for statement in [
            "UPDATE items SET hlc = hlc + 1",
            "UPDATE items SET device_id = zeroblob(16)",
        ] {
            let copy = f.path.with_extension("copy");
            std::fs::copy(&f.path, &copy).unwrap();
            sql(&copy, statement);
            let store = Store::open(&copy).unwrap();
            assert!(is_decrypt_error(
                &store.get_item::<Login>(&f.vk_p, id).unwrap_err()
            ));
            drop(store);
            std::fs::remove_file(&copy).unwrap();
        }

        // Relabelling the row as another domain is refused before any decryption.
        sql(&f.path, "UPDATE items SET domain = 2");
        let store = Store::open(&f.path).unwrap();
        assert!(matches!(
            store.get_item::<Login>(&f.vk_p, id),
            Err(VaultError::DomainMismatch)
        ));
        assert!(is_decrypt_error(
            &store.get_content(&f.vk_t, id).unwrap_err()
        ));
    }

    #[test]
    fn rows_cannot_be_moved_to_another_vault() {
        let mut f = fixture();
        let id = f.store.insert_item(&f.vk_p, login("pw-1")).unwrap();
        let row = f.store.current_row(id).unwrap().unwrap();

        let mut other = fixture();
        other.store.write_row(&row).unwrap();
        assert!(is_decrypt_error(
            &other.store.get_item::<Login>(&f.vk_p, id).unwrap_err()
        ));
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    /// The acceptance test of P1-08: nothing the user typed is readable in the file.
    #[test]
    fn the_vault_file_contains_no_plaintext() {
        let mut f = fixture();
        let secret_seed = b"TOTP-SEED-9f3a7c21e5".to_vec();
        let markers: [&[u8]; 12] = [
            b"MARKER-TITLE-Acme-Bank",
            b"marker.user@example.org",
            b"MARKER-PASSWORD-tr0ub4dor&3",
            b"https://marker.example.net/login",
            b"MARKER-NOTES-mother's maiden name",
            b"MARKER-NOTE-TITLE",
            b"MARKER-NOTE-BODY-the safe combination is 12-34-56",
            b"MARKER-ISSUER",
            &secret_seed,
            b"marker-rp.example.com",
            b"MARKER-PRIVATE-KEY-0123456789abcdef",
            b"MARKER-OLD-PASSWORD-before-rotation",
        ];

        let mut login = Login::new(
            "MARKER-TITLE-Acme-Bank",
            "marker.user@example.org",
            "MARKER-OLD-PASSWORD-before-rotation",
        )
        .with_url("https://marker.example.net/login");
        login.notes = "MARKER-NOTES-mother's maiden name".into();
        let login_id = f.store.insert_item(&f.vk_p, login.clone()).unwrap();
        // Rotate the password so the old one moves to the history table.
        login.password = "MARKER-PASSWORD-tr0ub4dor&3".into();
        f.store.update_item(&f.vk_p, login_id, login).unwrap();

        let note = SecureNote::new(
            "MARKER-NOTE-TITLE",
            "MARKER-NOTE-BODY-the safe combination is 12-34-56",
        );
        let note_id = f.store.insert_item(&f.vk_p, note).unwrap();
        f.store.delete_item::<Password>(note_id).unwrap();

        f.store
            .insert_item(
                &f.vk_t,
                TotpEntry::new("MARKER-ISSUER", "a", secret_seed.clone()),
            )
            .unwrap();
        let mut credential = passkey();
        credential.rp_id = "marker-rp.example.com".into();
        credential.private_key = b"MARKER-PRIVATE-KEY-0123456789abcdef".to_vec();
        f.store.insert_item(&f.vk_k, credential).unwrap();
        drop(f.store);

        let dir = f.path.parent().unwrap();
        let mut scanned = 0;
        for entry in std::fs::read_dir(dir).unwrap() {
            let bytes = std::fs::read(entry.unwrap().path()).unwrap();
            scanned += bytes.len();
            for marker in markers {
                assert!(
                    !contains(&bytes, marker),
                    "plaintext {:?} found in the vault file",
                    String::from_utf8_lossy(marker)
                );
                // Also in UTF-16, in case anything was stored as wide text.
                let wide: Vec<u8> = marker.iter().flat_map(|&b| [b, 0]).collect();
                assert!(!contains(&bytes, &wide));
            }
        }
        assert!(
            scanned > 4096,
            "the scan must have covered the database file"
        );

        // Sanity check of the scanner itself: a plaintext column would be caught.
        sql(
            &f.path,
            "INSERT INTO meta (key, value) VALUES ('leak', CAST('MARKER-ISSUER' AS BLOB))",
        );
        assert!(contains(&std::fs::read(&f.path).unwrap(), b"MARKER-ISSUER"));
    }
}

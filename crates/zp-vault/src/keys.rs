//! Generations of vault keys (`docs/spec/sync.md` §8).
//!
//! Revoking a device replaces the vault key of every domain, so that the revoked
//! device cannot read what is written afterwards. Old versions stay wrapped
//! under the old keys, so a domain has a *ring* of keys: one per generation
//! (`key_epoch`), or more than one where two devices rotated at the same time.
//!
//! A key slot holds one key of the ring. From it the others are reached through
//! what the vault file stores:
//!
//! * **key updates** lead forward: the key of generation `n`, wrapped under a
//!   key of generation `n - 1`. They are signed by the rotating device and
//!   travel with sync;
//! * **key links** lead anywhere: another key wrapped under the slot key. A
//!   device that joins after a rotation gets them for the older generations.

use rusqlite::{Connection, params};
use zeroize::Zeroizing;
use zp_crypto::{DeviceId, Domain, DomainId, KEY_LEN, Passkey, Password, Totp, VaultKey};
use zp_sync::{KeyUpdate, Revocation};

use crate::{Store, Vault, VaultError};

/// Where the item code gets vault keys from: a single key (generation 1), or
/// the ring of an unlocked domain.
pub trait KeySource<D: Domain> {
    /// The key new versions are written with, and its generation.
    fn write_key(&self) -> (u32, &VaultKey<D>);

    /// The keys of one generation. Usually one; none if that generation has not
    /// reached this device yet.
    fn keys_of(&self, epoch: u32) -> Vec<&VaultKey<D>>;

    /// Every key held.
    fn all_keys(&self) -> Vec<&VaultKey<D>>;
}

impl<D: Domain> KeySource<D> for VaultKey<D> {
    fn write_key(&self) -> (u32, &VaultKey<D>) {
        (1, self)
    }

    fn keys_of(&self, epoch: u32) -> Vec<&VaultKey<D>> {
        if epoch == 1 { vec![self] } else { Vec::new() }
    }

    fn all_keys(&self) -> Vec<&VaultKey<D>> {
        vec![self]
    }
}

struct Entry<D: Domain> {
    epoch: u32,
    key: VaultKey<D>,
    /// Whether a device that has been revoked since rotated to this key. Such a
    /// key still opens what was written with it, but is not written with.
    by_revoked: bool,
    /// Whether this is the key the slot holds.
    is_base: bool,
}

/// What the ring was built from, to notice when it is out of date.
type Stamp = (i64, i64);

/// The vault keys of one unlocked domain, of every generation this device can
/// reach.
pub struct KeyRing<D: Domain> {
    /// Ascending by generation, then by key bytes.
    entries: Vec<Entry<D>>,
    base: usize,
    write: usize,
    stamp: Stamp,
}

fn same_key<D: Domain>(a: &VaultKey<D>, b: &VaultKey<D>) -> bool {
    *a.to_transfer_bytes() == *b.to_transfer_bytes()
}

/// The first entry of the highest generation among those `allowed`.
fn newest<D: Domain>(entries: &[Entry<D>], allowed: impl Fn(&Entry<D>) -> bool) -> Option<usize> {
    let mut best: Option<usize> = None;
    for (index, entry) in entries.iter().enumerate() {
        if allowed(entry) && best.is_none_or(|best| entry.epoch > entries[best].epoch) {
            best = Some(index);
        }
    }
    best
}

impl<D: Domain> KeyRing<D> {
    fn assemble(mut entries: Vec<Entry<D>>, stamp: Stamp) -> Self {
        entries.sort_by(|a, b| {
            a.epoch.cmp(&b.epoch).then_with(|| {
                a.key
                    .to_transfer_bytes()
                    .as_slice()
                    .cmp(b.key.to_transfer_bytes().as_slice())
            })
        });
        let base = entries.iter().position(|entry| entry.is_base).unwrap_or(0);
        // Every device picks the same key of the newest generation. A key that
        // a revoked device chose is passed over if there is any other.
        let write = newest(&entries, |entry| !entry.by_revoked)
            .or_else(|| newest(&entries, |_| true))
            .unwrap_or(0);
        Self {
            entries,
            base,
            write,
            stamp,
        }
    }

    /// The key the slots of this device hold, and its generation.
    pub(crate) fn base(&self) -> (u32, &VaultKey<D>) {
        let entry = &self.entries[self.base];
        (entry.epoch, &entry.key)
    }

    /// A key of the newest generation held: what the next rotation starts from.
    fn newest(&self) -> (u32, &VaultKey<D>) {
        let entry = &self.entries[newest(&self.entries, |_| true).unwrap_or(0)];
        (entry.epoch, &entry.key)
    }

    /// The generation new versions are written with.
    pub fn epoch(&self) -> u32 {
        self.entries[self.write].epoch
    }

    /// Every key with its generation, for handing the domain to a device that
    /// joins. The key to write with comes last.
    pub(crate) fn export(&self) -> Vec<(u32, Zeroizing<[u8; KEY_LEN]>)> {
        let mut keys: Vec<_> = self
            .entries
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != self.write)
            .map(|(_, entry)| (entry.epoch, entry.key.to_transfer_bytes()))
            .collect();
        let write = &self.entries[self.write];
        keys.push((write.epoch, write.key.to_transfer_bytes()));
        keys
    }
}

impl<D: Domain> KeySource<D> for KeyRing<D> {
    fn write_key(&self) -> (u32, &VaultKey<D>) {
        let entry = &self.entries[self.write];
        (entry.epoch, &entry.key)
    }

    fn keys_of(&self, epoch: u32) -> Vec<&VaultKey<D>> {
        self.entries
            .iter()
            .filter(|entry| entry.epoch == epoch)
            .map(|entry| &entry.key)
            .collect()
    }

    fn all_keys(&self) -> Vec<&VaultKey<D>> {
        self.entries.iter().map(|entry| &entry.key).collect()
    }
}

impl<D: Domain> core::fmt::Debug for KeyRing<D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "KeyRing<{:?}>({} keys, generation {}, <redacted>)",
            D::ID,
            self.entries.len(),
            self.epoch()
        )
    }
}

struct Link {
    epoch: u32,
    under_epoch: u32,
    wrapped_key: Vec<u8>,
}

fn corrupt(_: impl Sized) -> VaultError {
    VaultError::Corrupt("malformed key update")
}

fn insert_key_update(conn: &Connection, update: &KeyUpdate) -> Result<usize, VaultError> {
    Ok(conn.execute(
        "INSERT OR IGNORE INTO key_updates (domain, epoch, device_id, wrapped_key, signature)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            update.domain.as_u8(),
            update.epoch,
            update.device_id.as_bytes(),
            update.wrapped_key,
            update.signature.as_slice(),
        ],
    )?)
}

impl Store {
    /// The key updates held, of one domain or of all.
    fn stored_key_updates(&self, domain: Option<DomainId>) -> Result<Vec<KeyUpdate>, VaultError> {
        let mut statement = self.conn.prepare_cached(
            "SELECT domain, epoch, device_id, wrapped_key, signature FROM key_updates
             WHERE ?1 IS NULL OR domain = ?1
             ORDER BY domain, epoch, device_id, wrapped_key",
        )?;
        let rows = statement.query_map(params![domain.map(DomainId::as_u8)], |row| {
            Ok((
                row.get::<_, u8>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
            ))
        })?;
        let mut updates = Vec::new();
        for row in rows {
            let (domain, epoch, device_id, wrapped_key, signature) = row?;
            updates.push(KeyUpdate {
                domain: DomainId::from_u8(domain).ok_or_else(|| corrupt(()))?,
                epoch,
                device_id: DeviceId::from_slice(&device_id).ok_or_else(|| corrupt(()))?,
                wrapped_key,
                signature: signature.try_into().map_err(corrupt)?,
            });
        }
        Ok(updates)
    }

    /// Every key update held: what a sync partner in good standing is offered.
    pub fn key_updates(&self) -> Result<Vec<KeyUpdate>, VaultError> {
        self.stored_key_updates(None)
    }

    /// Verifies key updates received from a sync partner against the registry
    /// and stores them. Returns how many were new. Needs no vault key: the
    /// domain applies them the next time it is used.
    pub fn merge_key_updates(&mut self, updates: Vec<KeyUpdate>) -> Result<usize, VaultError> {
        let registry = self.registry()?;
        let vault_id = self.vault_id();
        for update in &updates {
            update.verify(&vault_id, &registry)?;
        }
        let tx = self.conn.transaction()?;
        let mut added = 0;
        for update in &updates {
            added += insert_key_update(&tx, update)?;
        }
        tx.commit()?;
        Ok(added)
    }

    fn key_links(&self, domain: DomainId) -> Result<Vec<Link>, VaultError> {
        let mut statement = self.conn.prepare_cached(
            "SELECT epoch, under_epoch, wrapped_key FROM key_links WHERE domain = ?1
             ORDER BY epoch, under_epoch, wrapped_key",
        )?;
        let rows = statement.query_map(params![domain.as_u8()], |row| {
            Ok(Link {
                epoch: row.get(0)?,
                under_epoch: row.get(1)?,
                wrapped_key: row.get(2)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Stores `other` (generation `other_epoch`) wrapped under `under`
    /// (generation `under_epoch`), the key this device's slot holds.
    pub(crate) fn add_key_link<D: Domain>(
        &mut self,
        under: &VaultKey<D>,
        under_epoch: u32,
        other: &VaultKey<D>,
        other_epoch: u32,
    ) -> Result<(), VaultError> {
        let wrapped = under.wrap_linked(under_epoch, other, other_epoch, &self.vault_id())?;
        self.conn.execute(
            "INSERT INTO key_links (domain, epoch, under_epoch, wrapped_key)
             VALUES (?1, ?2, ?3, ?4)",
            params![D::ID.as_u8(), other_epoch, under_epoch, wrapped],
        )?;
        Ok(())
    }

    /// Changes whenever the ring of `domain` may have to be rebuilt: a key
    /// update arrived, or a device was revoked.
    fn key_stamp(&self, domain: DomainId) -> Result<Stamp, VaultError> {
        Ok(self.conn.query_row(
            "SELECT (SELECT count(*) FROM key_updates WHERE domain = ?1),
                    (SELECT count(*) FROM devices WHERE revoked_by IS NOT NULL)",
            params![domain.as_u8()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?)
    }

    /// Builds the ring of domain `D` from the key a slot of this device holds:
    /// follows every key update and key link that one of the keys found so far
    /// opens, until nothing new turns up.
    pub(crate) fn key_ring<D: Domain>(
        &self,
        base: VaultKey<D>,
        base_epoch: u32,
    ) -> Result<KeyRing<D>, VaultError> {
        let vault_id = self.vault_id();
        let stamp = self.key_stamp(D::ID)?;
        let updates = self.stored_key_updates(Some(D::ID))?;
        let links = self.key_links(D::ID)?;
        // Only rotations can make a key suspect; without any, the registry (which
        // a brand-new vault file does not have yet) is not needed.
        let registry = if updates.is_empty() {
            None
        } else {
            Some(self.registry()?)
        };

        let mut entries = vec![Entry {
            epoch: base_epoch,
            key: base,
            by_revoked: false,
            is_base: true,
        }];
        let add =
            |entries: &mut Vec<Entry<D>>, epoch: u32, key: VaultKey<D>, by_revoked| match entries
                .iter_mut()
                .find(|entry| entry.epoch == epoch && same_key(&entry.key, &key))
            {
                Some(entry) => entry.by_revoked |= by_revoked,
                None => entries.push(Entry {
                    epoch,
                    key,
                    by_revoked,
                    is_base: false,
                }),
            };
        let mut update_used = vec![false; updates.len()];
        let mut link_used = vec![false; links.len()];
        loop {
            let mut progressed = false;
            for (update, used) in updates.iter().zip(&mut update_used) {
                if *used {
                    continue;
                }
                let opened = entries
                    .iter()
                    .filter(|entry| entry.epoch.checked_add(1) == Some(update.epoch))
                    .find_map(|entry| {
                        entry
                            .key
                            .unwrap_successor(&vault_id, update.epoch, &update.wrapped_key)
                            .ok()
                    });
                if let Some(key) = opened {
                    let by_revoked = registry
                        .as_ref()
                        .is_some_and(|registry| registry.is_revoked(&update.device_id));
                    add(&mut entries, update.epoch, key, by_revoked);
                    *used = true;
                    progressed = true;
                }
            }
            for (link, used) in links.iter().zip(&mut link_used) {
                if *used {
                    continue;
                }
                let opened = entries
                    .iter()
                    .filter(|entry| entry.epoch == link.under_epoch)
                    .find_map(|entry| {
                        entry
                            .key
                            .unwrap_linked(
                                link.under_epoch,
                                link.epoch,
                                &vault_id,
                                &link.wrapped_key,
                            )
                            .ok()
                    });
                if let Some(key) = opened {
                    add(&mut entries, link.epoch, key, false);
                    *used = true;
                    progressed = true;
                }
            }
            if !progressed {
                break;
            }
        }
        Ok(KeyRing::assemble(entries, stamp))
    }

    /// The ring rebuilt from what the file holds now, if that differs from what
    /// `ring` was built from.
    pub(crate) fn refreshed<D: Domain>(
        &self,
        ring: &KeyRing<D>,
    ) -> Result<Option<KeyRing<D>>, VaultError> {
        if self.key_stamp(D::ID)? == ring.stamp {
            return Ok(None);
        }
        let (epoch, key) = ring.base();
        let base = VaultKey::from_transfer_bytes(&key.to_transfer_bytes());
        self.key_ring(base, epoch).map(Some)
    }

    /// Replaces the vault key of domain `D`: generates the key of the next
    /// generation and records the signed key update that lets the other devices
    /// follow. Returns the new generation.
    ///
    /// The new key is wrapped under a key of the newest generation held, which
    /// every device in good standing has or will receive. Rebuild the ring
    /// afterwards ([`Self::refreshed`]).
    pub(crate) fn rotate_key<D: Domain>(&mut self, ring: &KeyRing<D>) -> Result<u32, VaultError> {
        let signer = self.signer(ring)?;
        let (newest_epoch, newest_key) = ring.newest();
        let epoch = newest_epoch
            .checked_add(1)
            .ok_or(VaultError::Corrupt("key generations are exhausted"))?;
        let next = VaultKey::<D>::generate()?;
        let wrapped = newest_key.wrap_successor(&next, &self.vault_id(), epoch)?;
        let update = KeyUpdate::sign(
            &self.vault_id(),
            D::ID,
            epoch,
            self.device_id(),
            &signer,
            wrapped,
        );
        insert_key_update(&self.conn, &update)?;
        Ok(epoch)
    }
}

impl Vault {
    /// The generation of the vault key that domain `D` currently writes with.
    /// The domain must be unlocked.
    pub fn key_epoch<D: Domain>(&mut self) -> Result<u32, VaultError> {
        Ok(Self::key::<D>(&mut self.keys, &self.store, &self.auto_lock)?.epoch())
    }

    /// Replaces the vault key of domain `D`, which must be unlocked. Versions
    /// written from now on cannot be read with the previous keys; the other
    /// devices receive the new key with their next sync. Returns the new
    /// generation.
    pub fn rotate_key<D: Domain>(&mut self) -> Result<u32, VaultError> {
        let ring = Self::key::<D>(&mut self.keys, &self.store, &self.auto_lock)?;
        let epoch = self.store.rotate_key(ring)?;
        // Take the new key into use at once.
        Self::key::<D>(&mut self.keys, &self.store, &self.auto_lock)?;
        Ok(epoch)
    }

    /// Revokes a device: the others stop syncing with it as they learn of the
    /// revocation, and the vault key of every domain is replaced, so that the
    /// revoked device cannot read anything written from now on even if it gets
    /// hold of the ciphertext.
    ///
    /// Every domain of this vault must be unlocked, so revoking takes the master
    /// password *and* hardware verification on this device. Nothing is changed
    /// otherwise. What the revoked device has already received stays readable
    /// to it: change the passwords stored in the vault if the device was stolen.
    pub fn revoke_device(&mut self, device_id: DeviceId) -> Result<Revocation, VaultError> {
        if device_id == self.store.device_id() {
            return Err(VaultError::CannotRevokeSelf);
        }
        // Revoking again would only rotate the keys once more.
        if self.store.registry()?.is_revoked(&device_id) {
            return Err(zp_sync::SyncError::RevokedDevice(device_id).into());
        }
        // Check that everything needed is at hand before the first write.
        let (totp, passkey) = (
            self.has_domain(DomainId::Totp)?,
            self.has_domain(DomainId::Passkey)?,
        );
        Self::key::<Password>(&mut self.keys, &self.store, &self.auto_lock)?;
        if totp {
            Self::key::<Totp>(&mut self.keys, &self.store, &self.auto_lock)?;
        }
        if passkey {
            Self::key::<Passkey>(&mut self.keys, &self.store, &self.auto_lock)?;
        }

        let ring = Self::key::<Password>(&mut self.keys, &self.store, &self.auto_lock)?;
        let revocation = self.store.revoke_device(ring, device_id)?;
        self.rotate_key::<Password>()?;
        if totp {
            self.rotate_key::<Totp>()?;
        }
        if passkey {
            self.rotate_key::<Passkey>()?;
        }
        Ok(revocation)
    }
}

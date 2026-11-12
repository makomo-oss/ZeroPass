//! This device's identity and the device registry, as stored in the vault file
//! (`docs/spec/sync.md` §2.3 and §6, `docs/spec/pairing.md` §1).
//!
//! * The device **signing key** is stored wrapped under the vault key of each
//!   domain, so writing in a domain needs only that domain to be unlocked, and a
//!   locked vault cannot sign anything.
//! * The **channel key** is stored unwrapped (PoC; Phase 3 moves it to OS-protected
//!   storage): the sync channel must work while the vault is locked.
//! * The **registry** is stored in the clear and exchanged during sync.

use rusqlite::{Connection, OptionalExtension, params};
use zeroize::Zeroizing;
use zp_crypto::{ChannelKey, DeviceId, DeviceSigningKey, Domain, DomainId, SignPublicKey};
use zp_sync::{DeviceRecord, MAX_DEVICE_NAME_LEN, Registry, Revocation, VersionVector};

use crate::items::{COLUMNS, read_row, sign_row};
use crate::keys::KeySource;
use crate::store::{get_meta, set_meta};
use crate::{Store, VaultError};

const META_CHANNEL_KEY: &str = "channel_sk";

/// A device name taken from the environment (`COMPUTERNAME` / `HOSTNAME`), for
/// callers that have nothing better.
pub fn default_device_name() -> String {
    let name = ["COMPUTERNAME", "HOSTNAME"]
        .iter()
        .filter_map(|variable| std::env::var(variable).ok())
        .map(|name| {
            name.trim()
                .chars()
                .filter(|c| !c.is_control())
                .collect::<String>()
        })
        .find(|name| !name.is_empty())
        .unwrap_or_else(|| "device".to_owned());
    let mut end = name.len().min(MAX_DEVICE_NAME_LEN);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    name[..end].to_owned()
}

fn corrupt_registry(_: impl Sized) -> VaultError {
    VaultError::Corrupt("malformed device registry")
}

pub(crate) fn put_device_record(
    conn: &Connection,
    record: &DeviceRecord,
) -> Result<(), VaultError> {
    conn.execute(
        "INSERT OR IGNORE INTO devices
             (device_id, sign_pk, noise_pk, name, introduced_by, signature)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            record.device_id.as_bytes(),
            record.sign_pk.as_bytes(),
            record.noise_pk.as_slice(),
            record.name,
            record.introduced_by.as_bytes(),
            record.signature.as_slice(),
        ],
    )?;
    Ok(())
}

pub(crate) fn put_revocation(conn: &Connection, revocation: &Revocation) -> Result<(), VaultError> {
    conn.execute(
        "UPDATE devices SET revoked_by = ?2, revocation_signature = ?3
         WHERE device_id = ?1 AND revoked_by IS NULL",
        params![
            revocation.device_id.as_bytes(),
            revocation.revoked_by.as_bytes(),
            revocation.signature.as_slice(),
        ],
    )?;
    Ok(())
}

impl Store {
    /// Whether this device has an identity (a record in the registry).
    pub fn is_provisioned(&self) -> Result<bool, VaultError> {
        let found: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM devices WHERE device_id = ?1",
                params![self.device_id().as_bytes()],
                |row| row.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    /// Generates this device's signing key and channel key and stores the
    /// channel key. The device is not in the registry yet: a founding device adds
    /// its own root record ([`Self::provision_device`]), a joining device is
    /// introduced by an existing one and then calls [`Self::import_registry`].
    ///
    /// The returned signing key is not stored anywhere yet; wrap it for each
    /// domain with [`Self::add_device_key_slot`].
    pub fn create_identity(&mut self) -> Result<DeviceSigningKey, VaultError> {
        let signing_key = DeviceSigningKey::generate()?;
        self.adopt_channel_key(&ChannelKey::generate()?)?;
        Ok(signing_key)
    }

    /// Stores the channel key of a device that generated its keys before this
    /// file existed (a device joining through pairing).
    pub fn adopt_channel_key(&mut self, channel_key: &ChannelKey) -> Result<(), VaultError> {
        if self.is_provisioned()? {
            return Err(VaultError::Corrupt("this device already has an identity"));
        }
        let tx = self.conn.transaction()?;
        set_meta(&tx, META_CHANNEL_KEY, channel_key.secret_bytes())?;
        tx.execute("DELETE FROM device_keys", [])?;
        tx.commit()?;
        Ok(())
    }

    /// Gives the founding device of a vault its identity: fresh keys and a
    /// self-introduced record in the registry.
    ///
    /// The returned signing key is not stored anywhere yet; wrap it for each
    /// domain with [`Self::add_device_key_slot`].
    pub fn provision_device(&mut self, name: &str) -> Result<DeviceSigningKey, VaultError> {
        // Validate the name before anything is written.
        if name.len() > MAX_DEVICE_NAME_LEN || name.chars().any(char::is_control) {
            return Err(zp_sync::SyncError::MalformedDevice("invalid device name").into());
        }
        let signing_key = self.create_identity()?;
        let record = DeviceRecord::root(
            &self.vault_id(),
            self.device_id(),
            &signing_key,
            *self.channel_key()?.public_bytes(),
            name,
        )?;
        put_device_record(&self.conn, &record)?;
        Ok(signing_key)
    }

    /// Adds another device to the registry, vouched for by this device. Needs an
    /// unlocked domain to reach this device's signing key. Returns the signed
    /// record to hand to the new device.
    pub fn introduce_device<D: Domain>(
        &mut self,
        key: &impl KeySource<D>,
        device_id: DeviceId,
        sign_pk: SignPublicKey,
        noise_pk: zp_sync::ChannelPublicKey,
        name: &str,
    ) -> Result<DeviceRecord, VaultError> {
        let signer = self.signer(key)?;
        let record = DeviceRecord::introduce(
            &self.vault_id(),
            self.device_id(),
            &signer,
            device_id,
            sign_pk,
            noise_pk,
            name,
        )?;
        // Checks the record against the existing registry (conflicts, etc.).
        let mut registry = self.registry()?;
        registry.accept(record.clone())?;
        put_device_record(&self.conn, &record)?;
        Ok(record)
    }

    /// Revokes a device on behalf of this one. Needs an unlocked domain to reach
    /// this device's signing key.
    pub fn revoke_device<D: Domain>(
        &mut self,
        key: &impl KeySource<D>,
        device_id: DeviceId,
    ) -> Result<Revocation, VaultError> {
        let signer = self.signer(key)?;
        let revocation = Revocation::sign(&self.vault_id(), device_id, self.device_id(), &signer);
        let mut registry = self.registry()?;
        registry.accept_revocation(revocation.clone())?;
        put_revocation(&self.conn, &revocation)?;
        Ok(revocation)
    }

    /// Installs the registry a joining device received from the device that
    /// introduced it (a trusted source: the pairing channel). The records must
    /// include this device, with the keys generated by [`Self::create_identity`].
    pub fn import_registry(
        &mut self,
        signing_key: &DeviceSigningKey,
        records: Vec<DeviceRecord>,
        revocations: Vec<Revocation>,
    ) -> Result<(), VaultError> {
        let registry = Registry::from_trusted(self.vault_id(), records, revocations)?;
        let own = registry
            .get(&self.device_id())
            .ok_or(zp_sync::SyncError::UnknownDevice(self.device_id()))?;
        if own.sign_pk != signing_key.public_key()
            || &own.noise_pk != self.channel_key()?.public_bytes()
        {
            return Err(zp_sync::SyncError::ConflictingDevice(self.device_id()).into());
        }
        self.write_registry(&registry)
    }

    /// Persists every record and revocation of `registry` that is not stored yet.
    pub(crate) fn write_registry(&mut self, registry: &Registry) -> Result<(), VaultError> {
        let tx = self.conn.transaction()?;
        for record in registry.records() {
            put_device_record(&tx, record)?;
        }
        for revocation in registry.revocations() {
            put_revocation(&tx, revocation)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Stores the device signing key wrapped under the vault key of domain `D`,
    /// so that the domain can sign what it writes.
    pub fn add_device_key_slot<D: Domain>(
        &mut self,
        signing_key: &DeviceSigningKey,
        key: &impl KeySource<D>,
    ) -> Result<(), VaultError> {
        let blob = signing_key.wrap(key.write_key().1, &self.vault_id(), &self.device_id())?;
        self.conn.execute(
            "INSERT INTO device_keys (domain, blob) VALUES (?1, ?2)
             ON CONFLICT (domain) DO UPDATE SET blob = excluded.blob",
            params![D::ID.as_u8(), blob],
        )?;
        Ok(())
    }

    /// Whether the device signing key is available to domain `domain`.
    pub fn has_device_key_slot(&self, domain: DomainId) -> Result<bool, VaultError> {
        let found: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM device_keys WHERE domain = ?1",
                params![domain.as_u8()],
                |row| row.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    /// Unwraps the device signing key with the vault key of domain `D`.
    pub(crate) fn signer<D: Domain>(
        &self,
        key: &impl KeySource<D>,
    ) -> Result<DeviceSigningKey, VaultError> {
        let blob: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT blob FROM device_keys WHERE domain = ?1",
                params![D::ID.as_u8()],
                |row| row.get(0),
            )
            .optional()?;
        let blob = blob.ok_or(VaultError::DeviceKeyUnavailable(D::ID))?;
        // The slot was written with whichever key was current then.
        let mut signer = Err(VaultError::DeviceKeyUnavailable(D::ID));
        for candidate in key.all_keys() {
            signer =
                DeviceSigningKey::unwrap(candidate, &self.vault_id(), &self.device_id(), &blob)
                    .map_err(VaultError::from);
            if signer.is_ok() {
                break;
            }
        }
        signer
    }

    /// This device's key pair for the Noise channel.
    pub fn channel_key(&self) -> Result<ChannelKey, VaultError> {
        let secret = Zeroizing::new(
            get_meta(&self.conn, META_CHANNEL_KEY)?.ok_or(VaultError::NotProvisioned)?,
        );
        let secret: &[u8; 32] = secret.as_slice().try_into().map_err(corrupt_registry)?;
        Ok(ChannelKey::from_secret_bytes(secret))
    }

    /// Loads the device registry. Every stored record and revocation is verified
    /// again, so a registry that does not hang together is reported as corrupt
    /// rather than used.
    pub fn registry(&self) -> Result<Registry, VaultError> {
        let mut statement = self.conn.prepare(
            "SELECT device_id, sign_pk, noise_pk, name, introduced_by, signature,
                    revoked_by, revocation_signature
             FROM devices ORDER BY device_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Option<Vec<u8>>>(6)?,
                row.get::<_, Option<Vec<u8>>>(7)?,
            ))
        })?;

        let mut records = Vec::new();
        let mut revocations = Vec::new();
        for row in rows {
            let (
                device_id,
                sign_pk,
                noise_pk,
                name,
                introduced_by,
                signature,
                revoked_by,
                revocation,
            ) = row?;
            let device_id = DeviceId::from_slice(&device_id).ok_or_else(|| corrupt_registry(()))?;
            records.push(DeviceRecord {
                device_id,
                sign_pk: SignPublicKey::from_bytes(sign_pk.try_into().map_err(corrupt_registry)?),
                noise_pk: noise_pk.try_into().map_err(corrupt_registry)?,
                name,
                introduced_by: DeviceId::from_slice(&introduced_by)
                    .ok_or_else(|| corrupt_registry(()))?,
                signature: signature.try_into().map_err(corrupt_registry)?,
            });
            if let (Some(revoked_by), Some(signature)) = (revoked_by, revocation) {
                revocations.push(Revocation {
                    device_id,
                    revoked_by: DeviceId::from_slice(&revoked_by)
                        .ok_or_else(|| corrupt_registry(()))?,
                    signature: signature.try_into().map_err(corrupt_registry)?,
                });
            }
        }
        if records.is_empty() {
            return Err(VaultError::NotProvisioned);
        }
        Registry::from_trusted(self.vault_id(), records, revocations).map_err(corrupt_registry)
    }

    /// For each device, up to which sequence number its ops are held.
    pub fn version_vector(&self) -> Result<VersionVector, VaultError> {
        let mut statement = self
            .conn
            .prepare("SELECT device_id, seq FROM version_vector")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
        })?;
        let mut vector = VersionVector::new();
        for row in rows {
            let (device, seq) = row?;
            vector.advance(
                DeviceId::from_slice(&device)
                    .ok_or(VaultError::Corrupt("malformed version vector"))?,
                u64::try_from(seq).map_err(|_| VaultError::Corrupt("malformed version vector"))?,
            );
        }
        Ok(vector)
    }

    /// Signs the versions this device wrote in domain `D` before ops were signed
    /// (vault files created by an earlier format). Returns how many were signed.
    pub(crate) fn sign_unsigned<D: Domain>(
        &mut self,
        key: &impl KeySource<D>,
    ) -> Result<usize, VaultError> {
        let signer = self.signer(key)?;
        let (vault_id, device_id) = (self.vault_id(), self.device_id());
        let tx = self.conn.transaction()?;
        let mut signed = 0;
        for table in ["items", "item_history"] {
            let rows: Vec<_> = tx
                .prepare(&format!(
                    "SELECT {COLUMNS} FROM {table}
                     WHERE signature IS NULL AND device_id = ?1 AND domain = ?2"
                ))?
                .query_map(params![device_id.as_bytes(), D::ID.as_u8()], read_row)?
                .collect::<Result<_, _>>()?;
            for row in rows {
                let mut row = row?;
                sign_row(&mut row, &vault_id, &signer);
                tx.execute(
                    &format!("UPDATE {table} SET signature = ?1 WHERE device_id = ?2 AND seq = ?3"),
                    params![
                        row.signature.as_ref().map(|signature| signature.as_slice()),
                        device_id.as_bytes(),
                        i64::try_from(row.seq)
                            .map_err(|_| VaultError::Corrupt("sequence overflow"))?,
                    ],
                )?;
                signed += 1;
            }
        }
        tx.commit()?;
        Ok(signed)
    }

    /// Replaces this device's identity after the vault file was restored from a
    /// backup: a new device identifier, new keys, a new self-introduced record,
    /// and the revocation of every device that was in the registry before.
    ///
    /// The previous devices stay in the registry so that the ops they authored
    /// can still be verified.
    pub(crate) fn become_new_device(&mut self, name: &str) -> Result<DeviceSigningKey, VaultError> {
        let previous: Vec<DeviceId> = match self.registry() {
            Ok(registry) => registry.active().map(|record| record.device_id).collect(),
            Err(VaultError::NotProvisioned) => Vec::new(),
            Err(error) => return Err(error),
        };
        self.assign_new_device_id()?;
        let signing_key = self.provision_device(name)?;
        let (vault_id, device_id) = (self.vault_id(), self.device_id());
        let tx = self.conn.transaction()?;
        for device in previous {
            put_revocation(
                &tx,
                &Revocation::sign(&vault_id, device, device_id, &signing_key),
            )?;
        }
        tx.commit()?;
        Ok(signing_key)
    }
}

#[cfg(test)]
mod tests {
    use zp_crypto::{CryptoError, Password, Totp, VaultKey};

    use super::*;

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::create(&dir.path().join("vault.zpvault")).unwrap();
        (dir, store)
    }

    #[test]
    fn a_fresh_store_has_no_identity() {
        let (_dir, store) = store();
        assert!(!store.is_provisioned().unwrap());
        assert!(matches!(store.registry(), Err(VaultError::NotProvisioned)));
        assert!(matches!(
            store.channel_key(),
            Err(VaultError::NotProvisioned)
        ));
        assert!(store.version_vector().unwrap().is_empty());
    }

    #[test]
    fn provisioning_creates_a_verifiable_root_record() {
        let (_dir, mut store) = store();
        let signer = store.provision_device("Study PC").unwrap();
        assert!(store.is_provisioned().unwrap());

        let registry = store.registry().unwrap();
        let record = registry.get(&store.device_id()).unwrap();
        assert!(record.is_self_introduced());
        assert_eq!(record.name, "Study PC");
        assert_eq!(record.sign_pk, signer.public_key());
        assert_eq!(
            &record.noise_pk,
            store.channel_key().unwrap().public_bytes()
        );
        assert_eq!(registry.active().count(), 1);

        // Only once.
        assert!(matches!(
            store.provision_device("again"),
            Err(VaultError::Corrupt(_))
        ));
        // Invalid names are refused and leave nothing behind.
        let (_dir2, mut other) = self::store();
        assert!(other.provision_device(&"x".repeat(65)).is_err());
        assert!(!other.is_provisioned().unwrap());
    }

    #[test]
    fn the_signing_key_is_reachable_only_through_a_domain_with_a_slot() {
        let (_dir, mut store) = store();
        let signer = store.provision_device("pc").unwrap();
        let vk_p = VaultKey::<Password>::generate().unwrap();
        let vk_t = VaultKey::<Totp>::generate().unwrap();

        assert!(matches!(
            store.signer(&vk_p),
            Err(VaultError::DeviceKeyUnavailable(DomainId::Password))
        ));
        store.add_device_key_slot(&signer, &vk_p).unwrap();
        assert!(store.has_device_key_slot(DomainId::Password).unwrap());
        assert!(!store.has_device_key_slot(DomainId::Totp).unwrap());
        assert_eq!(
            store.signer(&vk_p).unwrap().public_key(),
            signer.public_key()
        );
        assert!(matches!(
            store.signer(&vk_t),
            Err(VaultError::DeviceKeyUnavailable(DomainId::Totp))
        ));

        // The wrong vault key cannot unwrap the slot.
        let other = VaultKey::<Password>::generate().unwrap();
        assert!(matches!(
            store.signer(&other),
            Err(VaultError::Crypto(CryptoError::Decrypt))
        ));

        store.add_device_key_slot(&signer, &vk_t).unwrap();
        assert_eq!(
            store.signer(&vk_t).unwrap().public_key(),
            signer.public_key()
        );
    }

    #[test]
    fn identity_survives_reopening() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.zpvault");
        let mut store = Store::create(&path).unwrap();
        let signer = store.provision_device("pc").unwrap();
        let vk = VaultKey::<Password>::generate().unwrap();
        store.add_device_key_slot(&signer, &vk).unwrap();
        let (registry, channel) = (
            store.registry().unwrap(),
            *store.channel_key().unwrap().public_bytes(),
        );
        drop(store);

        let store = Store::open(&path).unwrap();
        assert_eq!(store.registry().unwrap(), registry);
        assert_eq!(store.channel_key().unwrap().public_bytes(), &channel);
        assert_eq!(store.signer(&vk).unwrap().public_key(), signer.public_key());
    }

    #[test]
    fn a_tampered_registry_is_reported_as_corrupt() {
        let (_dir, mut store) = store();
        store.provision_device("pc").unwrap();
        store
            .conn
            .execute("UPDATE devices SET name = 'renamed'", [])
            .unwrap();
        assert!(matches!(store.registry(), Err(VaultError::Corrupt(_))));
    }

    #[test]
    fn becoming_a_new_device_revokes_the_previous_ones() {
        let (_dir, mut store) = store();
        let old_signer = store.provision_device("old pc").unwrap();
        let old_id = store.device_id();
        let vk = VaultKey::<Password>::generate().unwrap();
        store.add_device_key_slot(&old_signer, &vk).unwrap();

        let new_signer = store.become_new_device("new pc").unwrap();
        let new_id = store.device_id();
        assert_ne!(new_id, old_id);
        assert_ne!(new_signer.public_key(), old_signer.public_key());

        let registry = store.registry().unwrap();
        assert!(registry.is_revoked(&old_id));
        assert!(registry.is_active(&new_id));
        // The old device's key stays known, to verify the ops it authored.
        assert_eq!(registry.sign_pk(&old_id).unwrap(), &old_signer.public_key());
        // The old device's wrapped signing key is gone.
        assert!(!store.has_device_key_slot(DomainId::Password).unwrap());
    }

    #[test]
    fn default_device_names_are_valid() {
        let name = default_device_name();
        assert!(!name.is_empty() && name.len() <= MAX_DEVICE_NAME_LEN);
        assert!(!name.chars().any(char::is_control));
    }
}

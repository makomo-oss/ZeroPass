//! The vault file: a single SQLite database holding ciphertext and key slots.
//!
//! [`Store`] creates, opens and migrates the file and reads and writes rows. The
//! rows it handles are opaque: encryption happens in the `items` module, with keys
//! supplied by the caller for the duration of a call.

use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use zp_crypto::{DeviceId, VaultId};

use crate::VaultError;
use zp_sync::Hlc;

use crate::clock::Clock;
use crate::schema::{self, APPLICATION_ID, MIGRATIONS};

const META_VAULT_ID: &str = "vault_id";
const META_DEVICE_ID: &str = "device_id";
const META_CREATED_AT_MS: &str = "created_at_ms";

/// An open vault file.
#[derive(Debug)]
pub struct Store {
    pub(crate) conn: Connection,
    vault_id: VaultId,
    device_id: DeviceId,
    clock: Clock,
    hlc: Hlc,
}

impl Store {
    /// Creates a new, empty vault file with fresh vault and device identifiers.
    ///
    /// Fails with [`VaultError::AlreadyExists`] rather than touching an existing file.
    pub fn create(path: &Path) -> Result<Self, VaultError> {
        Self::create_with_clock(path, Clock::system())
    }

    /// Like [`Self::create`], with an explicit time source.
    pub fn create_with_clock(path: &Path, clock: Clock) -> Result<Self, VaultError> {
        if path.exists() {
            return Err(VaultError::AlreadyExists);
        }
        let result = Self::create_new(path, clock);
        if result.is_err() {
            // Do not leave a half-initialised file behind.
            let _ = std::fs::remove_file(path);
        }
        result
    }

    fn create_new(path: &Path, clock: Clock) -> Result<Self, VaultError> {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE;
        let mut conn = Connection::open_with_flags(path, flags)?;
        configure(&conn)?;
        conn.pragma_update(None, "application_id", APPLICATION_ID)?;
        schema::migrate(&mut conn, MIGRATIONS)?;

        let vault_id = VaultId::generate()?;
        let device_id = DeviceId::generate()?;
        let created_at_ms = clock.now_ms();
        let tx = conn.transaction()?;
        set_meta(&tx, META_VAULT_ID, vault_id.as_bytes())?;
        set_meta(&tx, META_DEVICE_ID, device_id.as_bytes())?;
        set_meta(&tx, META_CREATED_AT_MS, &created_at_ms.to_be_bytes())?;
        tx.commit()?;

        Ok(Self {
            conn,
            vault_id,
            device_id,
            clock,
            hlc: Hlc::resume_after(0),
        })
    }

    /// Opens an existing vault file, applying pending schema migrations.
    pub fn open(path: &Path) -> Result<Self, VaultError> {
        Self::open_with_clock(path, Clock::system())
    }

    /// Like [`Self::open`], with an explicit time source.
    pub fn open_with_clock(path: &Path, clock: Clock) -> Result<Self, VaultError> {
        if !path.exists() {
            return Err(VaultError::NotFound);
        }
        let mut conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;

        let application_id: i32 = conn
            .pragma_query_value(None, "application_id", |row| row.get(0))
            .map_err(not_a_database_as_not_a_vault)?;
        if application_id != APPLICATION_ID {
            return Err(VaultError::NotAVault);
        }
        if schema::user_version(&conn)? == 0 {
            return Err(VaultError::Corrupt("the schema was never initialised"));
        }
        configure(&conn)?;
        schema::migrate(&mut conn, MIGRATIONS)?;

        let vault_id = get_meta(&conn, META_VAULT_ID)?
            .as_deref()
            .and_then(VaultId::from_slice)
            .ok_or(VaultError::Corrupt("missing or malformed vault_id"))?;
        let device_id = get_meta(&conn, META_DEVICE_ID)?
            .as_deref()
            .and_then(DeviceId::from_slice)
            .ok_or(VaultError::Corrupt("missing or malformed device_id"))?;

        let newest_hlc: i64 = conn.query_row(
            "SELECT max(coalesce((SELECT max(hlc) FROM items), 0),
                        coalesce((SELECT max(hlc) FROM item_history), 0))",
            [],
            |row| row.get(0),
        )?;
        let newest_hlc =
            u64::try_from(newest_hlc).map_err(|_| VaultError::Corrupt("negative clock stamp"))?;

        Ok(Self {
            conn,
            vault_id,
            device_id,
            clock,
            hlc: Hlc::resume_after(newest_hlc),
        })
    }

    /// The identifier of this vault.
    pub fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    /// The identifier of this device's copy of the vault.
    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Issues the clock stamp for a new item version: greater than every stamp
    /// already in this vault.
    pub(crate) fn next_hlc(&mut self) -> Result<u64, VaultError> {
        self.hlc
            .tick(self.clock.now_ms())
            .ok_or(VaultError::ClockExhausted)
    }

    /// The current time according to this store's time source.
    pub(crate) fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    /// Gives this copy of the vault a fresh device identifier. Used when a vault
    /// file is restored on a new device, so two devices never share an identity.
    pub(crate) fn assign_new_device_id(&mut self) -> Result<(), VaultError> {
        let device_id = DeviceId::generate()?;
        set_meta(&self.conn, META_DEVICE_ID, device_id.as_bytes())?;
        self.device_id = device_id;
        Ok(())
    }

    /// The schema version of the open file.
    pub fn schema_version(&self) -> Result<u32, VaultError> {
        schema::user_version(&self.conn)
    }

    /// When the vault was created, in milliseconds since the Unix epoch.
    pub fn created_at_ms(&self) -> Result<u64, VaultError> {
        get_meta(&self.conn, META_CREATED_AT_MS)?
            .and_then(|value| value.try_into().ok())
            .map(u64::from_be_bytes)
            .ok_or(VaultError::Corrupt("missing or malformed created_at_ms"))
    }
}

/// Connection settings applied every time a vault file is opened.
fn configure(conn: &Connection) -> Result<(), VaultError> {
    conn.busy_timeout(Duration::from_secs(5))?;
    conn.execute_batch(
        "
        -- One self-contained file: a vault is backed up by copying it.
        PRAGMA journal_mode = DELETE;
        PRAGMA synchronous = FULL;
        -- Overwrite deleted rows instead of leaving them in free pages.
        PRAGMA secure_delete = ON;
        -- A crafted file must not be able to run SQL through views or triggers.
        PRAGMA trusted_schema = OFF;
        ",
    )?;
    Ok(())
}

fn not_a_database_as_not_a_vault(error: rusqlite::Error) -> VaultError {
    match error.sqlite_error_code() {
        Some(rusqlite::ErrorCode::NotADatabase) => VaultError::NotAVault,
        _ => VaultError::Database(error),
    }
}

fn get_meta(conn: &Connection, key: &str) -> Result<Option<Vec<u8>>, VaultError> {
    Ok(conn
        .query_row(
            "SELECT value FROM meta WHERE key = ?1",
            params![key],
            |row| row.get(0),
        )
        .optional()?)
}

fn set_meta(conn: &Connection, key: &str, value: &[u8]) -> Result<(), VaultError> {
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2)
         ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::SCHEMA_VERSION;

    fn dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn create_then_open_preserves_identity() {
        let dir = dir();
        let path = dir.path().join("vault.zpvault");

        let created = Store::create(&path).unwrap();
        let (vault_id, device_id) = (created.vault_id(), created.device_id());
        let created_at = created.created_at_ms().unwrap();
        assert!(created_at > 1_700_000_000_000);
        assert_eq!(created.schema_version().unwrap(), SCHEMA_VERSION);
        drop(created);

        let opened = Store::open(&path).unwrap();
        assert_eq!(opened.vault_id(), vault_id);
        assert_eq!(opened.device_id(), device_id);
        assert_eq!(opened.created_at_ms().unwrap(), created_at);
        assert_eq!(opened.schema_version().unwrap(), SCHEMA_VERSION);
    }

    #[test]
    fn every_vault_gets_its_own_identifiers() {
        let dir = dir();
        let a = Store::create(&dir.path().join("a.zpvault")).unwrap();
        let b = Store::create(&dir.path().join("b.zpvault")).unwrap();
        assert_ne!(a.vault_id(), b.vault_id());
        assert_ne!(a.device_id(), b.device_id());
    }

    #[test]
    fn create_refuses_to_overwrite() {
        let dir = dir();
        let path = dir.path().join("vault.zpvault");
        std::fs::write(&path, b"precious").unwrap();
        assert!(matches!(
            Store::create(&path),
            Err(VaultError::AlreadyExists)
        ));
        assert_eq!(std::fs::read(&path).unwrap(), b"precious");
    }

    #[test]
    fn open_requires_an_existing_file() {
        let dir = dir();
        let path = dir.path().join("missing.zpvault");
        assert!(matches!(Store::open(&path), Err(VaultError::NotFound)));
        assert!(!path.exists(), "open must not create the file");
    }

    #[test]
    fn open_rejects_files_that_are_not_vaults() {
        let dir = dir();

        let text = dir.path().join("notes.txt");
        std::fs::write(
            &text,
            "this is definitely not an SQLite database, just text",
        )
        .unwrap();
        assert!(matches!(Store::open(&text), Err(VaultError::NotAVault)));

        let other_db = dir.path().join("other.sqlite");
        Connection::open(&other_db)
            .unwrap()
            .execute_batch("CREATE TABLE t (x);")
            .unwrap();
        assert!(matches!(Store::open(&other_db), Err(VaultError::NotAVault)));
    }

    #[test]
    fn open_refuses_a_newer_schema() {
        let dir = dir();
        let path = dir.path().join("vault.zpvault");
        drop(Store::create(&path).unwrap());
        Connection::open(&path)
            .unwrap()
            .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .unwrap();
        assert!(matches!(
            Store::open(&path),
            Err(VaultError::UnsupportedSchema { .. })
        ));
    }

    #[test]
    fn open_detects_missing_identity() {
        let dir = dir();
        let path = dir.path().join("vault.zpvault");
        drop(Store::create(&path).unwrap());
        Connection::open(&path)
            .unwrap()
            .execute("DELETE FROM meta WHERE key = 'vault_id'", [])
            .unwrap();
        assert!(matches!(Store::open(&path), Err(VaultError::Corrupt(_))));
    }

    #[test]
    fn the_vault_is_a_single_file() {
        let dir = dir();
        let path = dir.path().join("vault.zpvault");
        drop(Store::create(&path).unwrap());
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names, ["vault.zpvault"]);
    }
}

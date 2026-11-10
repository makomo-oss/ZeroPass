//! The SQLite schema of a vault file and its migrations.
//!
//! Only ciphertext and the minimum routing metadata are stored in the clear:
//! `item_id`, `domain`, `hlc`, `device_id` and the tombstone flag. Everything else
//! about an item, including its kind and title, lives inside `ciphertext`.
//!
//! Migrations are append-only. `PRAGMA user_version` records how many have been
//! applied; a file with a higher version than this build knows is refused.

use rusqlite::Connection;

use crate::VaultError;

/// `PRAGMA application_id` of a vault file: ASCII "ZPV1".
pub(crate) const APPLICATION_ID: i32 = 0x5A50_5631;

/// Migration 1: the initial schema.
const MIGRATION_0001: &str = "
-- Vault-wide values: vault_id, device_id, created_at_ms.
CREATE TABLE meta (
    key   TEXT PRIMARY KEY NOT NULL,
    value BLOB NOT NULL
) STRICT, WITHOUT ROWID;

-- Wrapped vault keys (docs/spec/crypto.md §6).
--   domain: 1 = password, 2 = TOTP, 3 = passkey
--   kind:   1 = password, 2 = hardware, 3 = recovery
CREATE TABLE key_slots (
    domain    INTEGER NOT NULL CHECK (domain IN (1, 2, 3)),
    kind      INTEGER NOT NULL CHECK (kind IN (1, 2, 3)),
    blob      BLOB NOT NULL,
    kdf_salt  BLOB,
    kdf_m_kib INTEGER,
    kdf_t     INTEGER,
    kdf_p     INTEGER,
    PRIMARY KEY (domain, kind),
    -- The master password may only ever protect the password domain ...
    CHECK (kind <> 1 OR domain = 1),
    -- ... and hardware slots exist only for the TOTP and passkey domains.
    CHECK (kind <> 2 OR domain IN (2, 3)),
    -- KDF parameters accompany password slots, and only those.
    CHECK ((kind = 1) = (kdf_salt IS NOT NULL AND length(kdf_salt) = 16)),
    CHECK ((kind = 1) = (kdf_m_kib IS NOT NULL)),
    CHECK ((kind = 1) = (kdf_t IS NOT NULL)),
    CHECK ((kind = 1) = (kdf_p IS NOT NULL))
) STRICT, WITHOUT ROWID;

-- The current version of every item. A tombstone has deleted = 1 and no payload.
CREATE TABLE items (
    item_id     BLOB PRIMARY KEY NOT NULL CHECK (length(item_id) = 16),
    domain      INTEGER NOT NULL CHECK (domain IN (1, 2, 3)),
    hlc         INTEGER NOT NULL CHECK (hlc >= 0),
    device_id   BLOB NOT NULL CHECK (length(device_id) = 16),
    deleted     INTEGER NOT NULL CHECK (deleted IN (0, 1)),
    wrapped_dek BLOB,
    ciphertext  BLOB,
    CHECK ((deleted = 1) = (wrapped_dek IS NULL)),
    CHECK ((deleted = 1) = (ciphertext IS NULL))
) STRICT, WITHOUT ROWID;

CREATE INDEX items_live_by_domain ON items (domain) WHERE deleted = 0;

-- Superseded versions, kept so that an overwritten or conflicting edit can be
-- restored.
CREATE TABLE item_history (
    item_id     BLOB NOT NULL CHECK (length(item_id) = 16),
    hlc         INTEGER NOT NULL CHECK (hlc >= 0),
    device_id   BLOB NOT NULL CHECK (length(device_id) = 16),
    domain      INTEGER NOT NULL CHECK (domain IN (1, 2, 3)),
    deleted     INTEGER NOT NULL CHECK (deleted IN (0, 1)),
    wrapped_dek BLOB,
    ciphertext  BLOB,
    PRIMARY KEY (item_id, hlc, device_id),
    CHECK ((deleted = 1) = (wrapped_dek IS NULL)),
    CHECK ((deleted = 1) = (ciphertext IS NULL))
) STRICT, WITHOUT ROWID;
";

/// All migrations, in order. Never edit or remove an entry; append new ones.
pub(crate) const MIGRATIONS: &[&str] = &[MIGRATION_0001];

/// The schema version this build reads and writes.
pub const SCHEMA_VERSION: u32 = MIGRATIONS.len() as u32;

pub(crate) fn user_version(conn: &Connection) -> Result<u32, VaultError> {
    Ok(conn.pragma_query_value(None, "user_version", |row| row.get(0))?)
}

/// Applies the migrations the database has not seen yet, each in its own
/// transaction together with the version bump.
pub(crate) fn migrate(conn: &mut Connection, migrations: &[&str]) -> Result<(), VaultError> {
    let supported = migrations.len() as u32;
    let found = user_version(conn)?;
    if found > supported {
        return Err(VaultError::UnsupportedSchema { found, supported });
    }
    for (index, sql) in migrations.iter().enumerate().skip(found as usize) {
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        tx.pragma_update(None, "user_version", index as u32 + 1)?;
        tx.commit()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use rusqlite::params;

    use super::*;

    fn migrated() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        migrate(&mut conn, MIGRATIONS).unwrap();
        conn
    }

    #[test]
    fn fresh_database_reaches_the_current_version() {
        let conn = migrated();
        assert_eq!(user_version(&conn).unwrap(), SCHEMA_VERSION);
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(tables, ["item_history", "items", "key_slots", "meta"]);
    }

    #[test]
    fn migrating_twice_is_a_no_op() {
        let mut conn = migrated();
        migrate(&mut conn, MIGRATIONS).unwrap();
        assert_eq!(user_version(&conn).unwrap(), SCHEMA_VERSION);
    }

    #[test]
    fn pending_migrations_are_applied_in_order() {
        let mut conn = migrated();
        conn.execute("INSERT INTO meta (key, value) VALUES ('k', x'01')", [])
            .unwrap();

        let v2 = "ALTER TABLE meta ADD COLUMN note TEXT;";
        let v3 = "UPDATE meta SET note = 'migrated';";
        migrate(&mut conn, &[MIGRATION_0001, v2, v3]).unwrap();

        assert_eq!(user_version(&conn).unwrap(), 3);
        let note: String = conn
            .query_row("SELECT note FROM meta WHERE key = 'k'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(note, "migrated");
    }

    #[test]
    fn a_failing_migration_rolls_back_completely() {
        let mut conn = migrated();
        let broken = "CREATE TABLE extra (x INTEGER) STRICT; INSERT INTO nowhere VALUES (1);";
        assert!(matches!(
            migrate(&mut conn, &[MIGRATION_0001, broken]),
            Err(VaultError::Database(_))
        ));
        assert_eq!(user_version(&conn).unwrap(), 1);
        let extra: u32 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name = 'extra'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(extra, 0);
    }

    #[test]
    fn newer_schema_versions_are_refused() {
        let mut conn = migrated();
        conn.pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .unwrap();
        assert!(matches!(
            migrate(&mut conn, MIGRATIONS),
            Err(VaultError::UnsupportedSchema { found, supported })
                if found == SCHEMA_VERSION + 1 && supported == SCHEMA_VERSION
        ));
    }

    const SLOT: &str =
        "INSERT INTO key_slots (domain, kind, blob, kdf_salt, kdf_m_kib, kdf_t, kdf_p)
                        VALUES (?1, ?2, x'00', ?3, ?4, ?5, ?6)";

    #[test]
    fn password_slots_are_only_possible_for_the_password_domain() {
        let conn = migrated();
        let salt = vec![0u8; 16];
        conn.execute(SLOT, params![1, 1, salt, 19456, 2, 1])
            .unwrap();
        for domain in [2, 3] {
            assert!(
                conn.execute(SLOT, params![domain, 1, salt, 19456, 2, 1])
                    .is_err()
            );
        }
    }

    #[test]
    fn hardware_slots_are_only_possible_for_totp_and_passkey() {
        let conn = migrated();
        let none: Option<Vec<u8>> = None;
        let no_int: Option<i64> = None;
        assert!(
            conn.execute(SLOT, params![1, 2, none, no_int, no_int, no_int])
                .is_err()
        );
        conn.execute(SLOT, params![2, 2, none, no_int, no_int, no_int])
            .unwrap();
        conn.execute(SLOT, params![3, 2, none, no_int, no_int, no_int])
            .unwrap();
    }

    #[test]
    fn kdf_parameters_must_accompany_exactly_the_password_slots() {
        let conn = migrated();
        let none: Option<Vec<u8>> = None;
        let no_int: Option<i64> = None;
        // Password slot without parameters, or with a short salt.
        assert!(
            conn.execute(SLOT, params![1, 1, none, no_int, no_int, no_int])
                .is_err()
        );
        assert!(
            conn.execute(SLOT, params![1, 1, vec![0u8; 8], 19456, 2, 1])
                .is_err()
        );
        // Recovery slot with parameters.
        assert!(
            conn.execute(SLOT, params![1, 3, vec![0u8; 16], 19456, 2, 1])
                .is_err()
        );
        conn.execute(SLOT, params![1, 3, none, no_int, no_int, no_int])
            .unwrap();
    }

    #[test]
    fn item_rows_enforce_shape_and_tombstone_consistency() {
        let conn = migrated();
        let sql =
            "INSERT INTO items (item_id, domain, hlc, device_id, deleted, wrapped_dek, ciphertext)
                   VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)";
        let id = |b: u8| vec![b; 16];
        let blob = Some(vec![1u8, 2, 3]);
        let none: Option<Vec<u8>> = None;

        conn.execute(sql, params![id(1), 1, 10, id(9), 0, blob, blob])
            .unwrap();
        conn.execute(sql, params![id(2), 2, 10, id(9), 1, none, none])
            .unwrap();

        // Wrong id lengths, unknown domain, negative clock.
        assert!(
            conn.execute(sql, params![vec![3u8; 15], 1, 10, id(9), 0, blob, blob])
                .is_err()
        );
        assert!(
            conn.execute(sql, params![id(3), 1, 10, vec![9u8; 4], 0, blob, blob])
                .is_err()
        );
        assert!(
            conn.execute(sql, params![id(3), 4, 10, id(9), 0, blob, blob])
                .is_err()
        );
        assert!(
            conn.execute(sql, params![id(3), 1, -1, id(9), 0, blob, blob])
                .is_err()
        );
        // A live row needs a payload; a tombstone must not have one.
        assert!(
            conn.execute(sql, params![id(3), 1, 10, id(9), 0, none, none])
                .is_err()
        );
        assert!(
            conn.execute(sql, params![id(3), 1, 10, id(9), 1, blob, blob])
                .is_err()
        );
        assert!(
            conn.execute(sql, params![id(3), 1, 10, id(9), 0, blob, none])
                .is_err()
        );
    }
}

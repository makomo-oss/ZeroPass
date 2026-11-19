//! Passkey credential creation, lookup, and vault storage in the VK-K domain
//! (`docs/spec/passkey.md` §2).
//!
//! Private keys are generated inside this module, stored immediately in the
//! vault's `Passkey` domain (`VK-K`), and never returned by any public function.

use zp_crypto::{ItemId, Passkey};
use zp_vault::Vault;
use zp_vault::model::{Content, PasskeyCredential};

use crate::alg::{Algorithm, PublicKeyMaterial, generate_keypair};
use crate::error::PasskeyError;

/// Length of generated random credential identifiers (32 bytes).
pub const CREDENTIAL_ID_LEN: usize = 32;

/// Maximum length of a WebAuthn `user.id` handle (WebAuthn §5.4.3).
pub const MAX_USER_HANDLE_LEN: usize = 64;

/// Inputs required to create and store a passkey credential in the vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateParams {
    /// Canonical relying party identifier (already validated against origin).
    pub rp_id: String,
    /// Relying party display name.
    pub rp_name: String,
    /// Relying party's opaque user handle (1..=64 bytes).
    pub user_handle: Vec<u8>,
    /// User's account name.
    pub user_name: String,
    /// User's display name.
    pub user_display_name: String,
    /// Preferred COSE algorithms in priority order.
    pub algorithms: Vec<i32>,
    /// Existing credential IDs that must not already be registered for `rp_id`.
    pub exclude_credential_ids: Vec<Vec<u8>>,
}

/// Public summary of a stored passkey. Never contains private key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeySummary {
    /// Vault item identifier.
    pub item_id: ItemId,
    /// WebAuthn credential identifier.
    pub credential_id: Vec<u8>,
    /// Relying party identifier.
    pub rp_id: String,
    /// Relying party display name.
    pub rp_name: String,
    /// User handle.
    pub user_handle: Vec<u8>,
    /// User account name.
    pub user_name: String,
    /// User display name.
    pub user_display_name: String,
    /// Signature algorithm.
    pub algorithm: Algorithm,
}

/// Public output of creating and storing a passkey. Never contains the private
/// key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedCredential {
    /// Vault item identifier (existing item ID if an entry with the same
    /// `(rp_id, user_handle)` was replaced).
    pub item_id: ItemId,
    /// Generated 32-byte WebAuthn credential identifier.
    pub credential_id: Vec<u8>,
    /// Chosen COSE algorithm.
    pub algorithm: Algorithm,
    /// Encoded public key (COSE_Key CBOR and SPKI DER).
    pub public_key: PublicKeyMaterial,
}

/// Generates a new passkey key pair and stores it in `vault`'s `Passkey`
/// (`VK-K`) domain.
///
/// - Rejects invalid inputs (`rp_id`, `user_handle`, unsupported algorithms).
/// - Rejects registration with [`PasskeyError::CredentialExcluded`] if any ID
///   in `params.exclude_credential_ids` already exists for `params.rp_id`.
/// - Replaces an existing credential with the same `(rp_id, user_handle)` as
///   required for WebAuthn discoverable credentials.
pub fn create_credential(
    vault: &mut Vault,
    params: &CreateParams,
) -> Result<CreatedCredential, PasskeyError> {
    if params.rp_id.is_empty() || !params.rp_id.is_ascii() {
        return Err(PasskeyError::InvalidRpId(zp_origin::RpIdError::Malformed));
    }
    if params.user_handle.is_empty() || params.user_handle.len() > MAX_USER_HANDLE_LEN {
        return Err(PasskeyError::InvalidUserHandle);
    }
    let algorithm = Algorithm::select(&params.algorithms)?;

    // Inspect existing credentials in VK-K (also verifies the Passkey domain is
    // unlocked before we generate keys).
    let existing = vault.list::<Passkey>()?;
    let mut replace_item_id: Option<ItemId> = None;
    let mut used_cred_ids: Vec<Vec<u8>> = Vec::new();
    for (item_id, content) in existing {
        let Content::Passkey(cred) = content else {
            continue;
        };
        used_cred_ids.push(cred.credential_id.clone());
        if cred.rp_id != params.rp_id {
            continue;
        }
        if params
            .exclude_credential_ids
            .iter()
            .any(|excluded| excluded == &cred.credential_id)
        {
            return Err(PasskeyError::CredentialExcluded);
        }
        if cred.user_handle == params.user_handle {
            replace_item_id = Some(item_id);
        }
    }

    // Generate a unique 32-byte credential identifier.
    let credential_id = loop {
        let mut id = vec![0u8; CREDENTIAL_ID_LEN];
        getrandom::fill(&mut id).map_err(|_| PasskeyError::Rng)?;
        if !used_cred_ids.iter().any(|existing_id| existing_id == &id) {
            break id;
        }
    };

    let keypair = generate_keypair(algorithm)?;
    let stored = PasskeyCredential {
        rp_id: params.rp_id.clone(),
        rp_name: params.rp_name.clone(),
        user_handle: params.user_handle.clone(),
        user_name: params.user_name.clone(),
        user_display_name: params.user_display_name.clone(),
        credential_id: credential_id.clone(),
        private_key: keypair.private_key_pkcs8.as_slice().to_vec(),
        cose_algorithm: algorithm.cose_id(),
    };

    let item_id = match replace_item_id {
        Some(existing_id) => {
            vault.update(existing_id, stored)?;
            existing_id
        }
        None => vault.insert(stored)?,
    };

    Ok(CreatedCredential {
        item_id,
        credential_id,
        algorithm,
        public_key: keypair.public_key,
    })
}

/// Lists stored passkeys matching `rp_id` (and `allow_credential_ids` when
/// non-empty). Returns only public metadata, never private keys.
pub fn find_credentials(
    vault: &mut Vault,
    rp_id: &str,
    allow_credential_ids: &[Vec<u8>],
) -> Result<Vec<PasskeySummary>, PasskeyError> {
    let items = vault.list::<Passkey>()?;
    let mut matches = Vec::new();
    for (item_id, content) in items {
        let Content::Passkey(cred) = content else {
            continue;
        };
        if cred.rp_id != rp_id {
            continue;
        }
        if !allow_credential_ids.is_empty()
            && !allow_credential_ids
                .iter()
                .any(|allowed| allowed == &cred.credential_id)
        {
            continue;
        }
        let Some(algorithm) = Algorithm::from_cose(cred.cose_algorithm) else {
            continue;
        };
        matches.push(PasskeySummary {
            item_id,
            credential_id: cred.credential_id.clone(),
            rp_id: cred.rp_id.clone(),
            rp_name: cred.rp_name.clone(),
            user_handle: cred.user_handle.clone(),
            user_name: cred.user_name.clone(),
            user_display_name: cred.user_display_name.clone(),
            algorithm,
        });
    }
    matches.sort_by(|a, b| {
        a.user_name
            .to_lowercase()
            .cmp(&b.user_name.to_lowercase())
            .then_with(|| a.item_id.cmp(&b.item_id))
    });
    Ok(matches)
}

/// Loads a stored passkey credential for signing inside `zp-passkey`.
/// Not exposed outside this crate so private key material cannot escape.
pub(crate) fn load_for_signing(
    vault: &mut Vault,
    rp_id: &str,
    credential_id: &[u8],
) -> Result<(ItemId, PasskeyCredential), PasskeyError> {
    for (item_id, content) in vault.list::<Passkey>()? {
        let Content::Passkey(cred) = content else {
            continue;
        };
        if cred.rp_id == rp_id && cred.credential_id == credential_id {
            return Ok((item_id, cred));
        }
    }
    Err(PasskeyError::CredentialNotFound)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests may panic on setup errors")]

    use zp_crypto::{DomainId, InsecureSoftwareKeyStore, Passkey, Password};
    use zp_vault::{CreateOptions, KdfChoice, Vault, VaultError};

    use super::*;
    use crate::alg::{COSE_ALG_EDDSA, COSE_ALG_ES256, sign_raw, verify_raw};

    const MASTER_PASSWORD: &str = "correct horse battery staple";

    fn open_test_vault() -> (tempfile::TempDir, std::path::PathBuf, Vault) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("passkey.zpvault");
        let hw = InsecureSoftwareKeyStore::generate().unwrap();
        let vault = Vault::create(
            &path,
            MASTER_PASSWORD,
            Some(&hw),
            CreateOptions {
                kdf: KdfChoice::Fixed(zp_crypto::KdfParams::MINIMUM),
                ..CreateOptions::default()
            },
        )
        .unwrap();
        (dir, path, vault)
    }

    fn params(rp_id: &str, user_handle: &[u8], user_name: &str) -> CreateParams {
        CreateParams {
            rp_id: rp_id.into(),
            rp_name: "Example".into(),
            user_handle: user_handle.to_vec(),
            user_name: user_name.into(),
            user_display_name: "Alice".into(),
            algorithms: vec![COSE_ALG_ES256, COSE_ALG_EDDSA],
            exclude_credential_ids: Vec::new(),
        }
    }

    #[test]
    fn credentials_are_encrypted_in_vkk_and_never_plaintext_on_disk() {
        let (_dir, path, mut vault) = open_test_vault();
        let created = create_credential(
            &mut vault,
            &params(
                "unique-rp.example",
                b"alice-handle-01",
                "alice@unique.example",
            ),
        )
        .unwrap();
        assert_eq!(created.credential_id.len(), CREDENTIAL_ID_LEN);
        assert_eq!(created.algorithm, Algorithm::Es256);

        // Lock Password domain only: Passkey domain stays independently usable.
        vault.lock(DomainId::Password);
        let found = find_credentials(&mut vault, "unique-rp.example", &[]).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].credential_id, created.credential_id);

        // Lock Passkey domain and unlock Password only: passkey ops must fail with Locked(Passkey).
        vault.lock(DomainId::Passkey);
        vault.unlock_password(MASTER_PASSWORD).unwrap();
        assert!(matches!(
            create_credential(&mut vault, &params("other.example", b"bob", "bob")),
            Err(PasskeyError::Vault(VaultError::Locked(DomainId::Passkey)))
        ));
        assert!(matches!(
            find_credentials(&mut vault, "unique-rp.example", &[]),
            Err(PasskeyError::Vault(VaultError::Locked(DomainId::Passkey)))
        ));

        // On-disk SQLite file must not contain RP ID, user name, handle, or credential ID in plaintext.
        let disk = std::fs::read(&path).unwrap();
        for needle in [
            b"unique-rp.example".as_slice(),
            b"alice@unique.example".as_slice(),
            b"alice-handle-01".as_slice(),
            created.credential_id.as_slice(),
        ] {
            assert!(
                !disk.windows(needle.len()).any(|w| w == needle),
                "plaintext leaked on disk"
            );
        }
        assert!(vault.item_domain(created.item_id).unwrap() == Some(DomainId::Passkey));
    }

    #[test]
    fn exclude_credentials_replacement_and_allow_list_work() {
        let (_dir, _path, mut vault) = open_test_vault();
        let first = create_credential(&mut vault, &params("example.com", b"u1", "alice")).unwrap();

        // Excluding the existing credential ID for the same RP fails.
        let mut excluded = params("example.com", b"u2", "bob");
        excluded.exclude_credential_ids = vec![first.credential_id.clone()];
        assert!(matches!(
            create_credential(&mut vault, &excluded),
            Err(PasskeyError::CredentialExcluded)
        ));

        // The same credential ID on a different RP does not exclude.
        let mut other_rp = params("other.com", b"u2", "bob");
        other_rp.exclude_credential_ids = vec![first.credential_id.clone()];
        other_rp.algorithms = vec![COSE_ALG_EDDSA];
        let other = create_credential(&mut vault, &other_rp).unwrap();
        assert_eq!(other.algorithm, Algorithm::EdDsa);

        // Re-registering the same (rp_id, user_handle) replaces the existing item.
        let replaced =
            create_credential(&mut vault, &params("example.com", b"u1", "alice-new")).unwrap();
        assert_eq!(replaced.item_id, first.item_id);
        assert_ne!(replaced.credential_id, first.credential_id);

        let all_example = find_credentials(&mut vault, "example.com", &[]).unwrap();
        assert_eq!(all_example.len(), 1);
        assert_eq!(all_example[0].user_name, "alice-new");
        assert_eq!(all_example[0].credential_id, replaced.credential_id);

        // allowCredentials filters strictly by credential ID and RP ID.
        assert!(
            find_credentials(&mut vault, "example.com", &[first.credential_id])
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            find_credentials(
                &mut vault,
                "example.com",
                std::slice::from_ref(&replaced.credential_id)
            )
            .unwrap()
            .len(),
            1
        );

        // Stored key can sign and verify against the returned public key.
        let (_, stored) =
            load_for_signing(&mut vault, "example.com", &replaced.credential_id).unwrap();
        let sig = sign_raw(replaced.algorithm, &stored.private_key, b"challenge").unwrap();
        verify_raw(
            replaced.algorithm,
            &replaced.public_key.spki_der,
            b"challenge",
            &sig,
        )
        .unwrap();

        // Password domain has 0 items; Passkey domain has 2 items.
        assert!(vault.list::<Password>().unwrap().is_empty());
        assert_eq!(vault.list::<Passkey>().unwrap().len(), 2);
    }

    #[test]
    fn user_handle_and_rp_id_boundaries_are_enforced() {
        let (_dir, _path, mut vault) = open_test_vault();
        // Empty user handle is rejected.
        assert!(matches!(
            create_credential(&mut vault, &params("example.com", &[], "a")),
            Err(PasskeyError::InvalidUserHandle)
        ));
        // 65-byte user handle is rejected.
        assert!(matches!(
            create_credential(&mut vault, &params("example.com", &[1u8; 65], "a")),
            Err(PasskeyError::InvalidUserHandle)
        ));
        // 1-byte and 64-byte boundaries succeed.
        create_credential(&mut vault, &params("example.com", &[1u8; 1], "a1")).unwrap();
        create_credential(&mut vault, &params("example.com", &[2u8; 64], "a64")).unwrap();
        // Empty RP ID is rejected.
        assert!(matches!(
            create_credential(&mut vault, &params("", &[3u8; 4], "a")),
            Err(PasskeyError::InvalidRpId(_))
        ));
    }
}

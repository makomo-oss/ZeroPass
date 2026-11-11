//! Property tests of the item model, the TOTP engine and encrypted storage.

#![allow(clippy::unwrap_used, reason = "test helpers may panic")]

use proptest::collection::vec;
use proptest::prelude::*;
use zp_crypto::{DomainId, InsecureSoftwareKeyStore, KdfParams, Password, VaultKey};
use zp_vault::model::{Content, Item, Login, SecureNote, TotpAlgorithm, TotpEntry};
use zp_vault::totp;
use zp_vault::{CreateOptions, KdfChoice, Store, Vault};

fn login() -> impl Strategy<Value = Login> {
    (
        any::<String>(),
        any::<String>(),
        any::<String>(),
        vec(any::<String>(), 0..4),
        any::<String>(),
    )
        .prop_map(|(title, username, password, urls, notes)| {
            let mut login = Login::new(title, username, password);
            login.urls = urls;
            login.notes = notes;
            login
        })
}

fn algorithm() -> impl Strategy<Value = TotpAlgorithm> {
    prop_oneof![
        Just(TotpAlgorithm::Sha1),
        Just(TotpAlgorithm::Sha256),
        Just(TotpAlgorithm::Sha512)
    ]
}

fn totp_entry() -> impl Strategy<Value = TotpEntry> {
    (
        "[A-Za-z0-9 ]{0,16}",
        "[A-Za-z0-9@.]{0,24}",
        vec(any::<u8>(), 1..64),
        algorithm(),
        6u32..=8,
        1u32..=300,
    )
        .prop_map(|(issuer, account, secret, algorithm, digits, period)| {
            let mut entry = TotpEntry::new(issuer.trim(), account, secret);
            entry.algorithm = algorithm as i32;
            entry.digits = digits;
            entry.period = period;
            entry
        })
}

/// RFC 4648 Base32 without padding, the inverse of `totp::decode_base32`.
fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[(buffer >> bits) as usize & 31] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[(buffer << (5 - bits)) as usize & 31] as char);
    }
    out
}

fn percent_encode(text: &str) -> String {
    text.bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' => (byte as char).to_string(),
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

proptest! {
    #[test]
    fn content_round_trips_through_its_plaintext(
        login in login(),
        title in any::<String>(),
        body in any::<String>(),
        entry in totp_entry(),
    ) {
        for content in [
            login.clone().into_content(),
            SecureNote::new(title.clone(), body.clone()).into_content(),
            entry.clone().into_content(),
        ] {
            let plaintext = content.to_plaintext();
            let decoded = Content::from_plaintext(&plaintext, content.kind().domain()).unwrap();
            prop_assert_eq!(decoded, content);
        }
    }

    #[test]
    fn decoding_arbitrary_plaintext_never_panics(data in vec(any::<u8>(), 0..512)) {
        for domain in DomainId::ALL {
            if let Ok(content) = Content::from_plaintext(&data, domain) {
                // Whatever is accepted belongs to the row's domain and re-encodes.
                prop_assert_eq!(content.kind().domain(), domain);
                let again = Content::from_plaintext(&content.to_plaintext(), domain).unwrap();
                prop_assert_eq!(again, content);
            }
        }
    }

    #[test]
    fn base32_decoding_inverts_encoding(secret in vec(any::<u8>(), 1..=totp::MAX_SECRET_LEN)) {
        let encoded = base32(&secret);
        let decoded = totp::decode_base32(&encoded).unwrap();
        prop_assert_eq!(decoded.as_slice(), secret.as_slice());
        let lower = totp::decode_base32(&encoded.to_lowercase()).unwrap();
        prop_assert_eq!(lower.as_slice(), secret.as_slice());
    }

    #[test]
    fn parsing_arbitrary_text_never_panics(text in any::<String>(), tail in any::<String>()) {
        let _ = totp::parse_otpauth_uri(&text);
        let _ = totp::decode_base32(&text);
        // Also with a valid prefix, to reach the label and query parsing.
        if let Ok(entry) = totp::parse_otpauth_uri(&format!("otpauth://totp/{tail}")) {
            prop_assert!(totp::validate(&entry).is_ok());
        }
    }

    #[test]
    fn a_generated_uri_parses_back_to_the_entry(entry in totp_entry()) {
        let algorithm = match entry.algorithm() {
            TotpAlgorithm::Sha1 => "SHA1",
            TotpAlgorithm::Sha256 => "SHA256",
            TotpAlgorithm::Sha512 => "SHA512",
        };
        let uri = format!(
            "otpauth://totp/{}?secret={}&issuer={}&algorithm={algorithm}&digits={}&period={}",
            percent_encode(&entry.account),
            base32(&entry.secret),
            percent_encode(&entry.issuer),
            entry.digits,
            entry.period,
        );
        let mut expected = entry.clone();
        expected.account = entry.account.trim().to_owned();
        prop_assert_eq!(totp::parse_otpauth_uri(&uri).unwrap(), expected);
    }

    #[test]
    fn codes_have_the_requested_shape(entry in totp_entry(), time in any::<u64>()) {
        let code = totp::generate(&entry, time).unwrap();
        prop_assert_eq!(code.as_str().len(), entry.digits as usize);
        prop_assert!(code.as_str().bytes().all(|b| b.is_ascii_digit()));
        prop_assert!((1..=entry.period).contains(&code.seconds_remaining()));
        // The code is constant within a time step.
        let step_start = time - time % u64::from(entry.period);
        let at_start = totp::generate(&entry, step_start).unwrap();
        prop_assert_eq!(at_start.as_str(), code.as_str());
    }
}

proptest! {
    // File-backed cases are slower; a few dozen are plenty.
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn stored_logins_read_back_exactly(logins in vec(login(), 1..6)) {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::create(&dir.path().join("vault.zpvault")).unwrap();
        let key = VaultKey::<Password>::generate().unwrap();

        let mut ids = Vec::new();
        for login in &logins {
            ids.push(store.insert_item(&key, login.clone()).unwrap());
        }
        for (id, login) in ids.iter().zip(&logins) {
            prop_assert_eq!(&store.get_item::<Login>(&key, *id).unwrap(), login);
        }
        prop_assert_eq!(store.list_items(&key).unwrap().len(), logins.len());

        // Updating keeps every earlier version, newest first.
        let id = ids[0];
        for login in logins.iter().skip(1) {
            store.update_item(&key, id, login.clone()).unwrap();
        }
        let history = store.item_history(&key, id).unwrap();
        prop_assert_eq!(history.len(), logins.len() - 1);
        prop_assert!(history.windows(2).all(|pair| pair[0].hlc > pair[1].hlc));
    }
}

#[test]
fn a_vault_survives_a_full_cycle_with_arbitrary_unicode() {
    // One deterministic end-to-end case with awkward text, through `Vault`.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.zpvault");
    let hardware = InsecureSoftwareKeyStore::generate().unwrap();
    let options = CreateOptions {
        kdf: KdfChoice::Fixed(KdfParams::MINIMUM),
        clock: None,
    };
    let password = "パスワード🔑 with spaces\tand\u{0301} marks";

    let mut vault = Vault::create(&path, password, Some(&hardware), options).unwrap();
    let login = Login::new(
        "銀行 \u{202e}txet",
        "ユーザー\0name",
        "p\u{00e9}ss\nword\r\n",
    );
    let id = vault.insert(login.clone()).unwrap();
    drop(vault);

    let mut vault = Vault::open(&path).unwrap();
    vault.unlock_password(password).unwrap();
    assert_eq!(vault.get::<Login>(id).unwrap(), login);
}

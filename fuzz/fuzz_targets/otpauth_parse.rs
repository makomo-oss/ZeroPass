//! Fuzzes the `otpauth://` URI parser and the Base32 decoder.
//!
//! Parsing must never panic; anything accepted must be a valid entry that can
//! generate codes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use zp_vault::totp;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(secret) = totp::decode_base32(text) {
        assert!(!secret.is_empty() && secret.len() <= totp::MAX_SECRET_LEN);
    }

    // As given, and behind a valid prefix so the label and query are reached.
    for uri in [text.to_owned(), format!("otpauth://totp/{text}")] {
        let Ok(entry) = totp::parse_otpauth_uri(&uri) else {
            continue;
        };
        totp::validate(&entry).expect("a parsed entry is valid");
        for time in [0, 59, 1_700_000_000, u64::MAX] {
            let code = totp::generate(&entry, time).expect("a valid entry generates codes");
            assert_eq!(code.as_str().len(), entry.digits as usize);
            assert!((1..=entry.period).contains(&code.seconds_remaining()));
        }
    }
});

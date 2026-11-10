//! Fuzzes the decoding of decrypted item content (protobuf).
//!
//! Decoding must never panic; anything accepted must belong to the row's domain
//! and survive re-encoding unchanged.
#![no_main]

use libfuzzer_sys::fuzz_target;
use zp_crypto::DomainId;
use zp_vault::model::Content;
use zp_vault::totp;

fuzz_target!(|data: &[u8]| {
    for domain in DomainId::ALL {
        let Ok(content) = Content::from_plaintext(data, domain) else {
            continue;
        };
        assert_eq!(content.kind().domain(), domain);
        let _ = content.title();

        let encoded = content.to_plaintext();
        let again = Content::from_plaintext(&encoded, domain).expect("re-encoded content decodes");
        assert_eq!(again, content);

        // A decoded TOTP entry holds attacker-chosen parameters: generating a
        // code must reject bad ones instead of panicking.
        if let Content::Totp(entry) = &content {
            if let Ok(code) = totp::generate(entry, 1_700_000_000) {
                assert_eq!(code.as_str().len(), entry.digits as usize);
            }
        }
    }
});

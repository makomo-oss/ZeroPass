//! The printable form of the recovery key (`docs/spec/crypto.md` §8).
//!
//! ```text
//! code  = CrockfordBase32(RK(32) ‖ check(2)), 55 symbols in groups of five
//! check = SHA-256("zeropass/v1/recovery-check" ‖ RK)[..2]
//! ```
//!
//! Crockford's alphabet has no `I`, `L`, `O` or `U`, so a code copied by hand
//! cannot confuse them with `1` and `0`; the check bytes catch other slips.

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::CryptoError;
use crate::keywrap::RecoveryKey;
use crate::mem::SecretBytes;
use crate::secret::KEY_LEN;

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CHECK_LABEL: &[u8] = b"zeropass/v1/recovery-check";
const CHECK_LEN: usize = 2;
const PAYLOAD_LEN: usize = KEY_LEN + CHECK_LEN;
/// 34 bytes are 272 bits: 55 five-bit symbols, the last carrying 3 padding bits.
const SYMBOLS: usize = 55;
const GROUP: usize = 5;

fn check(key: &[u8; KEY_LEN]) -> [u8; CHECK_LEN] {
    let digest = Sha256::new()
        .chain_update(CHECK_LABEL)
        .chain_update(key)
        .finalize();
    [digest[0], digest[1]]
}

/// The value of one symbol, accepting lower case and the look-alikes `O`, `I`, `L`.
fn symbol_value(symbol: u8) -> Option<u8> {
    let symbol = match symbol.to_ascii_uppercase() {
        b'O' => b'0',
        b'I' | b'L' => b'1',
        other => other,
    };
    ALPHABET
        .iter()
        .position(|&candidate| candidate == symbol)
        .map(|index| index as u8)
}

impl RecoveryKey {
    /// Formats the key for the user to write down: eleven dash-separated groups of
    /// five characters, for example `7ZK2M-0Q4XA-…`.
    pub fn to_code(&self) -> Zeroizing<String> {
        let mut payload = Zeroizing::new([0u8; PAYLOAD_LEN]);
        payload[..KEY_LEN].copy_from_slice(self.0.expose());
        payload[KEY_LEN..].copy_from_slice(&check(self.0.expose()));

        let mut code = Zeroizing::new(String::with_capacity(SYMBOLS + SYMBOLS / GROUP));
        let (mut buffer, mut bits) = (0u32, 0u32);
        let mut written = 0;
        let mut push = |code: &mut String, value: u32| {
            if written > 0 && written % GROUP == 0 {
                code.push('-');
            }
            code.push(ALPHABET[value as usize & 31] as char);
            written += 1;
        };
        for &byte in payload.iter() {
            buffer = (buffer << 8) | u32::from(byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                push(&mut code, buffer >> bits);
            }
            buffer &= (1 << bits) - 1;
        }
        if bits > 0 {
            push(&mut code, buffer << (5 - bits));
        }
        buffer.zeroize();
        code
    }

    /// Parses a code typed by the user. Case, dashes and whitespace are ignored,
    /// and `O` / `I` / `L` are read as `0` / `1` / `1`.
    ///
    /// Every malformed input, including a failed check, gives
    /// [`CryptoError::InvalidRecoveryKey`]. A well-formed code for a *different*
    /// vault parses fine; it is rejected later when it fails to open the slots.
    pub fn from_code(code: &str) -> Result<Self, CryptoError> {
        let mut payload = Zeroizing::new([0u8; PAYLOAD_LEN]);
        let (mut buffer, mut bits) = (0u32, 0u32);
        let (mut symbols, mut written) = (0usize, 0usize);
        for byte in code.bytes() {
            if byte == b'-' || byte.is_ascii_whitespace() {
                continue;
            }
            let value = symbol_value(byte).ok_or(CryptoError::InvalidRecoveryKey)?;
            symbols += 1;
            if symbols > SYMBOLS {
                return Err(CryptoError::InvalidRecoveryKey);
            }
            buffer = (buffer << 5) | u32::from(value);
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                payload[written] = (buffer >> bits) as u8;
                written += 1;
                buffer &= (1 << bits) - 1;
            }
        }
        // All symbols present, and the padding bits of the last one are zero.
        let complete = symbols == SYMBOLS && written == PAYLOAD_LEN && buffer == 0;
        buffer.zeroize();
        if !complete {
            return Err(CryptoError::InvalidRecoveryKey);
        }

        let mut key = SecretBytes::zeroed(true);
        key.expose_mut().copy_from_slice(&payload[..KEY_LEN]);
        if payload[KEY_LEN..] != check(key.expose()) {
            return Err(CryptoError::InvalidRecoveryKey);
        }
        Ok(Self(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(bytes: [u8; KEY_LEN]) -> RecoveryKey {
        let mut secret = SecretBytes::zeroed(false);
        secret.expose_mut().copy_from_slice(&bytes);
        RecoveryKey(secret)
    }

    #[test]
    fn codes_have_eleven_groups_of_five_crockford_symbols() {
        let code = RecoveryKey::generate().unwrap().to_code();
        let groups: Vec<&str> = code.split('-').collect();
        assert_eq!(groups.len(), 11);
        assert!(groups.iter().all(|group| group.len() == 5));
        assert!(code.bytes().all(|b| b == b'-' || ALPHABET.contains(&b)));
        assert!(!code.contains(['I', 'L', 'O', 'U']));
    }

    #[test]
    fn known_keys_have_known_codes() {
        // All-zero key: 32 zero bytes, then the check bytes.
        let zero = key([0; KEY_LEN]).to_code();
        assert!(zero.starts_with("00000-00000-00000-00000-00000-00000-00000-00000-00000-00000-0"));
        let [c0, c1] = check(&[0; KEY_LEN]);
        // Bits 256..271 are the check; symbol 51 starts at bit 255.
        let tail: String = zero.chars().filter(|&c| c != '-').skip(51).collect();
        let expected = [
            ALPHABET[usize::from(c0 >> 4)],
            ALPHABET[usize::from((c0 & 0x0F) << 1 | c1 >> 7)],
            ALPHABET[usize::from((c1 >> 2) & 31)],
            ALPHABET[usize::from((c1 & 0x03) << 3)],
        ];
        assert_eq!(tail.as_bytes(), expected);

        // 0xFF.. gives 'Z' (31) for every full symbol of the key.
        let ones = key([0xFF; KEY_LEN]).to_code();
        assert!(ones.starts_with("ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-Z"));
    }

    #[test]
    fn codes_round_trip() {
        for _ in 0..64 {
            let original = RecoveryKey::generate().unwrap();
            let parsed = RecoveryKey::from_code(&original.to_code()).unwrap();
            assert_eq!(parsed.0.expose(), original.0.expose());
        }
    }

    #[test]
    fn parsing_is_forgiving_about_how_the_code_is_typed() {
        let original = key([0x5A; KEY_LEN]);
        let code = original.to_code();
        let variants = [
            code.to_lowercase(),
            code.replace('-', ""),
            code.replace('-', " "),
            format!("  {}\r\n", code.replace('-', " - ")),
            code.replace('0', "O").replace('1', "l"),
            code.replace('0', "o").replace('1', "I"),
        ];
        for variant in variants {
            let parsed = RecoveryKey::from_code(&variant).unwrap();
            assert_eq!(parsed.0.expose(), original.0.expose(), "{variant:?}");
        }
    }

    #[test]
    fn a_single_wrong_character_is_caught() {
        let code = key([0x5A; KEY_LEN]).to_code();
        let symbols: Vec<char> = code.chars().collect();
        let mut caught = 0;
        let mut tried = 0;
        for (index, &original) in symbols.iter().enumerate() {
            if original == '-' {
                continue;
            }
            for &replacement in ALPHABET.iter() {
                let replacement = replacement as char;
                if replacement == original {
                    continue;
                }
                let mut changed = symbols.clone();
                changed[index] = replacement;
                tried += 1;
                if RecoveryKey::from_code(&changed.iter().collect::<String>()).is_err() {
                    caught += 1;
                }
            }
        }
        // A 16-bit check misses about 1 in 65 536 random errors.
        assert!(tried > 1500);
        assert!(
            tried - caught <= 2,
            "{} of {tried} substitutions slipped through",
            tried - caught
        );
    }

    #[test]
    fn swapped_neighbours_are_caught() {
        let code: Vec<char> = key([0x5A; KEY_LEN])
            .to_code()
            .chars()
            .filter(|&c| c != '-')
            .collect();
        let other: Vec<char> = RecoveryKey::generate()
            .unwrap()
            .to_code()
            .chars()
            .filter(|&c| c != '-')
            .collect();
        let mut missed = 0;
        for code in [code, other] {
            for index in 0..code.len() - 1 {
                if code[index] == code[index + 1] {
                    continue;
                }
                let mut swapped = code.clone();
                swapped.swap(index, index + 1);
                if RecoveryKey::from_code(&swapped.iter().collect::<String>()).is_ok() {
                    missed += 1;
                }
            }
        }
        // Allow for one rare collision of the 16-bit check.
        assert!(missed <= 1, "{missed} transpositions slipped through");
    }

    #[test]
    fn malformed_codes_are_rejected() {
        let code = key([0x5A; KEY_LEN]).to_code();
        let cases = [
            String::new(),
            "-----".into(),
            code[..code.len() - 1].to_owned(),
            format!("{}0", code.as_str()),
            format!("{}-00000", code.as_str()),
            code.replacen(|c: char| c != '-', "U", 1),
            code.replacen(|c: char| c != '-', "!", 1),
            code.replacen(|c: char| c != '-', "é", 1),
            "0".repeat(SYMBOLS),
        ];
        for case in cases {
            assert_eq!(
                RecoveryKey::from_code(&case).unwrap_err(),
                CryptoError::InvalidRecoveryKey,
                "{case:?}"
            );
        }
        // Non-zero padding bits in the final symbol.
        let mut symbols: Vec<char> = code.chars().collect();
        let last = symbols.len() - 1;
        let value = symbol_value(symbols[last] as u8).unwrap();
        symbols[last] = ALPHABET[usize::from(value | 0b001)] as char;
        assert!(RecoveryKey::from_code(&symbols.iter().collect::<String>()).is_err());
    }
}

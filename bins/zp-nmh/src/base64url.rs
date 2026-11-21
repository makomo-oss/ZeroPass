//! Base64url without padding (RFC 4648 §5): how the extension and the bridge
//! write the bytes of WebAuthn (challenges, identifiers, signatures) in JSON,
//! as the browser's `toJSON()` of a credential does.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |n, (index, byte)| {
            n | u32::from(*byte) << (16 - 8 * index)
        });
        for index in 0..=chunk.len() {
            out.push(char::from(
                ALPHABET[(n >> (18 - 6 * index)) as usize & 0x3f],
            ));
        }
    }
    out
}

/// Reads unpadded base64url strictly: no padding, no other alphabet, no
/// leftover bits.
pub(crate) fn decode(text: &str) -> Option<Vec<u8>> {
    let value = |symbol: u8| ALPHABET.iter().position(|&c| c == symbol).map(|v| v as u32);
    if text.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    for chunk in text.as_bytes().chunks(4) {
        let mut n = 0u32;
        for (index, symbol) in chunk.iter().enumerate() {
            n |= value(*symbol)? << (18 - 6 * index);
        }
        let bytes = n.to_be_bytes();
        let whole = chunk.len() - 1;
        // The bits after the last whole byte must be zero (canonical form).
        if whole < 3 && bytes[1 + whole] != 0 {
            return None;
        }
        out.extend_from_slice(&bytes[1..=whole]);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_matches_rfc_4648() {
        for (input, output) in [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(input.as_bytes()), output);
            assert_eq!(decode(output).unwrap(), input.as_bytes());
        }
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(decode(&encode(&all)).unwrap(), all);
        assert_eq!(encode(&[0xfb, 0xff, 0xbf]), "-_-_");
    }

    #[test]
    fn anything_else_is_refused() {
        for bad in ["Zg==", "Z", "Zm9v+", "Zm9v/", "Zh", "Zm9", "Zm 9v", "é"] {
            assert_eq!(decode(bad), None, "{bad}");
        }
        // "Zm9" would be "fo" with leftover bits; "Zm8" is the canonical form.
        assert_eq!(decode("Zm8").unwrap(), b"fo");
    }
}

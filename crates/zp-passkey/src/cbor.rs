//! A writer for the few CBOR values WebAuthn needs (RFC 8949): integers, byte
//! strings, and maps of definite length.
//!
//! The authenticator only ever writes CBOR, never reads it, and always in the
//! same shapes (a COSE key, an attestation object). The caller writes map
//! entries in the canonical order of CTAP2 (shorter encoded keys first, then
//! byte-wise), which is what relying parties and the test vectors expect.

/// CBOR major types.
const UNSIGNED: u8 = 0;
const NEGATIVE: u8 = 1;
const BYTES: u8 = 2;
const MAP: u8 = 5;

/// Builds a CBOR encoding.
#[derive(Default)]
pub(crate) struct Cbor(Vec<u8>);

impl Cbor {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// A data item's head: its major type and its argument, in the shortest
    /// form (preferred serialisation).
    fn head(&mut self, major: u8, argument: u64) {
        let major = major << 5;
        if argument < 24 {
            // Fits in the initial byte.
            self.0.push(major | argument as u8);
        } else if let Ok(byte) = u8::try_from(argument) {
            self.0.extend_from_slice(&[major | 24, byte]);
        } else if let Ok(short) = u16::try_from(argument) {
            self.0.push(major | 25);
            self.0.extend_from_slice(&short.to_be_bytes());
        } else if let Ok(word) = u32::try_from(argument) {
            self.0.push(major | 26);
            self.0.extend_from_slice(&word.to_be_bytes());
        } else {
            self.0.push(major | 27);
            self.0.extend_from_slice(&argument.to_be_bytes());
        }
    }

    /// An integer.
    pub(crate) fn int(&mut self, value: i64) -> &mut Self {
        match u64::try_from(value) {
            Ok(unsigned) => self.head(UNSIGNED, unsigned),
            // -1 - value, which is non-negative and fits.
            Err(_) => self.head(NEGATIVE, !(value as u64)),
        }
        self
    }

    /// A byte string.
    pub(crate) fn bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.head(BYTES, bytes.len() as u64);
        self.0.extend_from_slice(bytes);
        self
    }

    /// The start of a map of `entries` key-value pairs; the keys and values
    /// follow, in order.
    pub(crate) fn map(&mut self, entries: usize) -> &mut Self {
        self.head(MAP, entries as u64);
        self
    }

    pub(crate) fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// RFC 8949, Appendix A.
    #[test]
    fn encodings_match_the_rfc_examples() {
        let int = |value: i64| hex(&Cbor::new().int(value).finish());
        assert_eq!(int(0), "00");
        assert_eq!(int(23), "17");
        assert_eq!(int(24), "1818");
        assert_eq!(int(100), "1864");
        assert_eq!(int(1000), "1903e8");
        assert_eq!(int(1_000_000), "1a000f4240");
        assert_eq!(int(1_000_000_000_000), "1b000000e8d4a51000");
        assert_eq!(int(-1), "20");
        assert_eq!(int(-10), "29");
        assert_eq!(int(-100), "3863");
        assert_eq!(int(-1000), "3903e7");
        assert_eq!(int(i64::MIN), "3b7fffffffffffffff");
        assert_eq!(hex(&Cbor::new().bytes(&[]).finish()), "40");
        assert_eq!(
            hex(&Cbor::new().bytes(&[1, 2, 3, 4]).finish()),
            "4401020304"
        );
        assert_eq!(hex(&Cbor::new().map(0).finish()), "a0");
        let map = Cbor::new().map(2).int(1).int(2).int(3).int(4).finish();
        assert_eq!(hex(&map), "a201020304");
    }

    #[test]
    fn long_strings_get_a_longer_head() {
        assert_eq!(&Cbor::new().bytes(&[0; 24]).finish()[..2], [0x58, 24]);
        assert_eq!(&Cbor::new().bytes(&[0; 256]).finish()[..3], [0x59, 1, 0]);
    }
}

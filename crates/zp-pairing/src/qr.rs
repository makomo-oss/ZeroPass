//! The pairing offer shown as a QR code (`docs/spec/pairing.md` §3.2).
//!
//! ```text
//! text    = "ZP1:" ‖ Base64URL-without-padding(payload)
//! payload = version(1) ‖ role(1) ‖ psk(32) ‖ noise_pk(32) ‖ expires_at(8) ‖ hint count(1) ‖ hints
//! ```
//!
//! The offer carries a one-time secret: whoever reads it within its lifetime
//! can complete the pairing handshake. It must only ever be shown on the screen
//! of the device, never sent over a network or logged.

use core::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use zeroize::Zeroizing;
use zp_crypto::{CryptoError, rng};

use crate::PairingError;
use crate::noise::{ChannelPublicKey, PSK_LEN};

const PREFIX: &str = "ZP1:";
const VERSION: u8 = 0x01;
/// How long an offer is valid.
pub const OFFER_LIFETIME_SECS: u64 = 60;
/// Most connection hints an offer may carry.
pub const MAX_HINTS: usize = 8;

const HINT_IPV4: u8 = 0x01;
const HINT_IPV6: u8 = 0x02;
const HINT_BLE: u8 = 0x03;

/// Which side of the pairing the device showing the offer is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfferRole {
    /// The displaying device already has the vault and will admit the scanner.
    Existing,
    /// The displaying device is new and asks the scanner to admit it.
    New,
}

/// How to reach the device showing the offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hint {
    /// A TCP endpoint on the local network.
    Socket(SocketAddr),
    /// Bluetooth LE; how to find the device is defined in `ble.md`.
    Ble,
}

/// A pairing offer.
#[derive(Clone, PartialEq, Eq)]
pub struct PairingOffer {
    /// The role of the device showing the offer.
    pub role: OfferRole,
    /// The one-time secret mixed into the pairing handshake.
    pub psk: Zeroizing<[u8; PSK_LEN]>,
    /// The channel key of the device showing the offer. The scanner checks that
    /// the handshake authenticated exactly this key.
    pub noise_pk: ChannelPublicKey,
    /// When the offer expires, in seconds since the Unix epoch.
    pub expires_at: u64,
    /// How to reach the device showing the offer.
    pub hints: Vec<Hint>,
}

impl fmt::Debug for PairingOffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingOffer")
            .field("role", &self.role)
            .field("psk", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .field("hints", &self.hints)
            .finish_non_exhaustive()
    }
}

impl PairingOffer {
    /// Creates an offer with a fresh one-time secret, valid for
    /// [`OFFER_LIFETIME_SECS`] from `now_secs`.
    pub fn new(
        role: OfferRole,
        noise_pk: ChannelPublicKey,
        hints: Vec<Hint>,
        now_secs: u64,
    ) -> Result<Self, CryptoError> {
        Ok(Self {
            role,
            psk: Zeroizing::new(rng::array()?),
            noise_pk,
            expires_at: now_secs.saturating_add(OFFER_LIFETIME_SECS),
            hints: hints.into_iter().take(MAX_HINTS).collect(),
        })
    }

    /// Whether the offer has expired at `now_secs`.
    pub fn is_expired(&self, now_secs: u64) -> bool {
        now_secs > self.expires_at
    }

    /// The text to show as a QR code (or to type in by hand).
    pub fn to_text(&self) -> Zeroizing<String> {
        let mut payload = Zeroizing::new(Vec::with_capacity(75 + self.hints.len() * 19));
        payload.push(VERSION);
        payload.push(match self.role {
            OfferRole::Existing => 0x01,
            OfferRole::New => 0x02,
        });
        payload.extend_from_slice(self.psk.as_slice());
        payload.extend_from_slice(&self.noise_pk);
        payload.extend_from_slice(&self.expires_at.to_be_bytes());
        let hints = &self.hints[..self.hints.len().min(MAX_HINTS)];
        payload.push(hints.len() as u8);
        for hint in hints {
            match hint {
                Hint::Socket(SocketAddr::V4(address)) => {
                    payload.push(HINT_IPV4);
                    payload.extend_from_slice(&address.ip().octets());
                    payload.extend_from_slice(&address.port().to_be_bytes());
                }
                Hint::Socket(SocketAddr::V6(address)) => {
                    payload.push(HINT_IPV6);
                    payload.extend_from_slice(&address.ip().octets());
                    payload.extend_from_slice(&address.port().to_be_bytes());
                }
                Hint::Ble => payload.push(HINT_BLE),
            }
        }
        let mut text = Zeroizing::new(String::with_capacity(
            PREFIX.len() + payload.len() * 4 / 3 + 3,
        ));
        text.push_str(PREFIX);
        base64url_encode(&payload, &mut text);
        text
    }

    /// Parses the text of a scanned code and refuses it if it has expired.
    ///
    /// Every malformed input gives [`PairingError::InvalidOffer`].
    pub fn parse(text: &str, now_secs: u64) -> Result<Self, PairingError> {
        let encoded = text
            .trim()
            .strip_prefix(PREFIX)
            .ok_or(PairingError::InvalidOffer)?;
        let payload = Zeroizing::new(base64url_decode(encoded).ok_or(PairingError::InvalidOffer)?);
        let mut reader = Reader(&payload);

        if reader.byte()? != VERSION {
            return Err(PairingError::InvalidOffer);
        }
        let role = match reader.byte()? {
            0x01 => OfferRole::Existing,
            0x02 => OfferRole::New,
            _ => return Err(PairingError::InvalidOffer),
        };
        let psk = Zeroizing::new(reader.array::<PSK_LEN>()?);
        let noise_pk = reader.array()?;
        let expires_at = u64::from_be_bytes(reader.array()?);
        let count = usize::from(reader.byte()?);
        if count > MAX_HINTS {
            return Err(PairingError::InvalidOffer);
        }
        let mut hints = Vec::with_capacity(count);
        for _ in 0..count {
            hints.push(match reader.byte()? {
                HINT_IPV4 => {
                    let ip = Ipv4Addr::from(reader.array::<4>()?);
                    Hint::Socket(SocketAddr::new(
                        ip.into(),
                        u16::from_be_bytes(reader.array()?),
                    ))
                }
                HINT_IPV6 => {
                    let ip = Ipv6Addr::from(reader.array::<16>()?);
                    Hint::Socket(SocketAddr::new(
                        ip.into(),
                        u16::from_be_bytes(reader.array()?),
                    ))
                }
                HINT_BLE => Hint::Ble,
                _ => return Err(PairingError::InvalidOffer),
            });
        }
        if !reader.0.is_empty() {
            return Err(PairingError::InvalidOffer);
        }

        let offer = Self {
            role,
            psk,
            noise_pk,
            expires_at,
            hints,
        };
        if offer.is_expired(now_secs) {
            return Err(PairingError::OfferExpired);
        }
        Ok(offer)
    }
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn byte(&mut self) -> Result<u8, PairingError> {
        Ok(self.array::<1>()?[0])
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], PairingError> {
        let (head, rest) = self
            .0
            .split_first_chunk::<N>()
            .ok_or(PairingError::InvalidOffer)?;
        self.0 = rest;
        Ok(*head)
    }
}

const BASE64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64url_encode(bytes: &[u8], out: &mut String) {
    for chunk in bytes.chunks(3) {
        let group = chunk
            .iter()
            .fold(0u32, |acc, &byte| acc << 8 | u32::from(byte))
            << (8 * (3 - chunk.len()));
        for index in 0..=chunk.len() {
            out.push(BASE64URL[(group >> (18 - 6 * index)) as usize & 63] as char);
        }
    }
}

/// Decodes unpadded Base64URL. Rejects other characters, impossible lengths and
/// non-canonical encodings (set bits in the unused tail).
fn base64url_decode(text: &str) -> Option<Vec<u8>> {
    let symbols = text.as_bytes();
    if symbols.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(symbols.len() * 3 / 4);
    for chunk in symbols.chunks(4) {
        let mut group = 0u32;
        for &symbol in chunk {
            let value = BASE64URL
                .iter()
                .position(|&candidate| candidate == symbol)?;
            group = group << 6 | value as u32;
        }
        group <<= 6 * (4 - chunk.len());
        let bytes = chunk.len() - 1;
        // The bits beyond the decoded bytes must be zero.
        if group & ((1 << (8 * (3 - bytes))) - 1) != 0 {
            return None;
        }
        out.extend_from_slice(&group.to_be_bytes()[1..=bytes]);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn offer(hints: Vec<Hint>) -> PairingOffer {
        PairingOffer::new(OfferRole::Existing, [7; 32], hints, NOW).unwrap()
    }

    fn socket(text: &str) -> Hint {
        Hint::Socket(text.parse().unwrap())
    }

    #[test]
    fn offers_round_trip_through_their_text() {
        let offers = [
            offer(vec![]),
            offer(vec![socket("192.168.1.20:47000"), Hint::Ble]),
            offer(vec![
                socket("[fe80::1234:5678:9abc:def0]:47001"),
                socket("10.0.0.5:1"),
            ]),
            PairingOffer::new(OfferRole::New, [9; 32], vec![Hint::Ble], NOW).unwrap(),
        ];
        for original in offers {
            let text = original.to_text();
            assert!(text.starts_with("ZP1:"));
            assert!(
                text.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_:".contains(&b))
            );
            assert_eq!(PairingOffer::parse(&text, NOW).unwrap(), original);
            // Surrounding whitespace from copy and paste is tolerated.
            assert_eq!(
                PairingOffer::parse(&format!("  {}\n", text.as_str()), NOW).unwrap(),
                original
            );
        }
    }

    #[test]
    fn every_offer_has_a_fresh_secret_and_a_short_life() {
        let (a, b) = (offer(vec![]), offer(vec![]));
        assert_ne!(a.psk, b.psk);
        assert_eq!(a.expires_at, NOW + OFFER_LIFETIME_SECS);
        assert!(!a.is_expired(NOW + OFFER_LIFETIME_SECS));
        assert!(a.is_expired(NOW + OFFER_LIFETIME_SECS + 1));
    }

    #[test]
    fn expired_offers_are_refused() {
        let text = offer(vec![]).to_text();
        assert!(PairingOffer::parse(&text, NOW + 60).is_ok());
        assert_eq!(
            PairingOffer::parse(&text, NOW + 61).unwrap_err(),
            PairingError::OfferExpired
        );
    }

    #[test]
    fn the_text_fits_a_qr_code_and_hides_nothing_else() {
        let text = offer(vec![
            socket("192.168.1.20:47000"),
            socket("[fe80::1]:47000"),
            Hint::Ble,
        ])
        .to_text();
        // Well within what a phone camera reads comfortably (QR version 10 or so).
        assert!(text.len() < 200, "{} characters", text.len());
        let shown = format!("{:?}", offer(vec![]));
        assert!(shown.contains("<redacted>"));
    }

    #[test]
    fn at_most_eight_hints_are_carried() {
        let many = offer(
            (0..20)
                .map(|n| socket(&format!("10.0.0.{n}:4000")))
                .collect(),
        );
        assert_eq!(many.hints.len(), MAX_HINTS);
        assert_eq!(
            PairingOffer::parse(&many.to_text(), NOW)
                .unwrap()
                .hints
                .len(),
            MAX_HINTS
        );
    }

    #[test]
    fn malformed_offers_are_refused() {
        let good = offer(vec![socket("192.168.1.20:47000")]).to_text();
        let payload = base64url_decode(good.strip_prefix(PREFIX).unwrap()).unwrap();
        let reencode = |bytes: &[u8]| {
            let mut text = String::from(PREFIX);
            base64url_encode(bytes, &mut text);
            text
        };
        let mut cases: Vec<String> = vec![
            String::new(),
            "ZP1:".into(),
            "ZP2:AAAA".into(),
            good.strip_prefix("ZP1:").unwrap().to_owned(),
            format!("{}!", good.as_str()),
            format!("{}=", good.as_str()),
            "ZP1:日本語".into(),
            reencode(&payload[..payload.len() - 1]),
            reencode(&[payload.as_slice(), &[0]].concat()),
        ];
        // Unknown version, role, hint type; a hint count beyond the limit or the data.
        for (index, value) in [(0, 2u8), (1, 3), (74, 9), (74, 2), (75, 0x7F)] {
            let mut bad = payload.clone();
            bad[index] = value;
            cases.push(reencode(&bad));
        }
        for case in cases {
            assert_eq!(
                PairingOffer::parse(&case, NOW).unwrap_err(),
                PairingError::InvalidOffer,
                "{case:?}"
            );
        }
    }

    #[test]
    fn base64url_matches_rfc_4648_vectors() {
        let cases: [(&[u8], &str); 7] = [
            (b"", ""),
            (b"f", "Zg"),
            (b"fo", "Zm8"),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg"),
            (b"fooba", "Zm9vYmE"),
            (b"foobar", "Zm9vYmFy"),
        ];
        for (bytes, text) in cases {
            let mut encoded = String::new();
            base64url_encode(bytes, &mut encoded);
            assert_eq!(encoded, text);
            assert_eq!(base64url_decode(text).as_deref(), Some(bytes));
        }
        // The URL-safe alphabet.
        let mut encoded = String::new();
        base64url_encode(&[0xFB, 0xFF], &mut encoded);
        assert_eq!(encoded, "-_8");
        // Non-canonical and impossible inputs.
        for bad in ["Z", "Zh", "Zm9", "Zm9vY", "Zg==", "Z g", "+/8"] {
            assert_eq!(base64url_decode(bad), None, "{bad:?}");
        }
    }

    proptest! {
        #[test]
        fn base64url_round_trips(bytes in proptest::collection::vec(any::<u8>(), 0..200)) {
            let mut text = String::new();
            base64url_encode(&bytes, &mut text);
            prop_assert_eq!(base64url_decode(&text), Some(bytes));
        }

        #[test]
        fn arbitrary_text_never_panics(text in any::<String>(), tail in "[A-Za-z0-9_-]{0,160}") {
            let _ = PairingOffer::parse(&text, NOW);
            let _ = PairingOffer::parse(&format!("ZP1:{tail}"), NOW);
        }
    }
}

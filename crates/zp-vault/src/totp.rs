//! Time-based one-time passwords (RFC 6238) and `otpauth://` URIs.
//!
//! TOTP seeds live in the TOTP domain, so producing a code through
//! [`Vault::totp_code`](crate::Vault::totp_code) requires that domain to be
//! unlocked by the hardware key store. The functions here are pure: they take the
//! entry and the time.

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

use crate::model::{TotpAlgorithm, TotpEntry};

/// Longest `otpauth://` URI accepted.
pub const MAX_URI_LEN: usize = 4096;
/// Longest secret accepted, in bytes.
pub const MAX_SECRET_LEN: usize = 256;
/// Longest time step accepted, in seconds (one day).
pub const MAX_PERIOD: u32 = 86_400;

/// Why a TOTP entry or URI was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TotpError {
    /// The URI does not start with `otpauth://`.
    #[error("not an otpauth:// URI")]
    NotOtpauth,
    /// The URI describes something other than TOTP (for example HOTP).
    #[error("only otpauth://totp/ URIs are supported")]
    UnsupportedType,
    /// The URI is longer than [`MAX_URI_LEN`].
    #[error("the URI is too long")]
    UriTooLong,
    /// A percent-encoded sequence is malformed or not valid UTF-8.
    #[error("the URI contains an invalid percent-encoding")]
    InvalidEncoding,
    /// The URI has no `secret` parameter.
    #[error("the URI has no secret")]
    MissingSecret,
    /// The secret is not valid Base32, is empty, or is too long.
    #[error("the secret is not valid")]
    InvalidSecret,
    /// The algorithm is not SHA1, SHA256 or SHA512.
    #[error("unsupported algorithm")]
    InvalidAlgorithm,
    /// The number of digits is not between 6 and 8.
    #[error("the number of digits must be between 6 and 8")]
    InvalidDigits,
    /// The period is zero, too long, or not a number.
    #[error("the period is not valid")]
    InvalidPeriod,
}

/// A generated one-time code. The digits are wiped on drop and never printed by
/// `Debug`.
pub struct TotpCode {
    code: Zeroizing<String>,
    seconds_remaining: u32,
}

impl TotpCode {
    /// The code, zero-padded to the entry's number of digits.
    pub fn as_str(&self) -> &str {
        &self.code
    }

    /// How many seconds the code remains valid (at least 1).
    pub fn seconds_remaining(&self) -> u32 {
        self.seconds_remaining
    }
}

impl core::fmt::Debug for TotpCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "TotpCode(<redacted>, {}s remaining)",
            self.seconds_remaining
        )
    }
}

/// Checks the parameters of an entry.
pub fn validate(entry: &TotpEntry) -> Result<(), TotpError> {
    if entry.secret.is_empty() || entry.secret.len() > MAX_SECRET_LEN {
        return Err(TotpError::InvalidSecret);
    }
    if TotpAlgorithm::try_from(entry.algorithm).is_err() {
        return Err(TotpError::InvalidAlgorithm);
    }
    if !(6..=8).contains(&entry.digits) {
        return Err(TotpError::InvalidDigits);
    }
    if !(1..=MAX_PERIOD).contains(&entry.period) {
        return Err(TotpError::InvalidPeriod);
    }
    Ok(())
}

fn hmac_of(algorithm: TotpAlgorithm, secret: &[u8], message: &[u8]) -> Zeroizing<Vec<u8>> {
    macro_rules! mac {
        ($hash:ty) => {{
            // HMAC accepts keys of any length, so construction cannot fail.
            let mut mac = <Hmac<$hash> as KeyInit>::new_from_slice(secret)
                .unwrap_or_else(|_| unreachable!("HMAC accepts keys of any length"));
            mac.update(message);
            Zeroizing::new(mac.finalize().into_bytes().to_vec())
        }};
    }
    match algorithm {
        TotpAlgorithm::Sha1 => mac!(Sha1),
        TotpAlgorithm::Sha256 => mac!(Sha256),
        TotpAlgorithm::Sha512 => mac!(Sha512),
    }
}

/// Generates the code of `entry` for the given Unix time in seconds.
pub fn generate(entry: &TotpEntry, unix_time_secs: u64) -> Result<TotpCode, TotpError> {
    validate(entry)?;
    let algorithm =
        TotpAlgorithm::try_from(entry.algorithm).map_err(|_| TotpError::InvalidAlgorithm)?;
    let period = u64::from(entry.period);
    let counter = unix_time_secs / period;

    let mac = hmac_of(algorithm, &entry.secret, &counter.to_be_bytes());
    // Dynamic truncation (RFC 4226 §5.3).
    let offset = usize::from(mac[mac.len() - 1] & 0x0f);
    let binary = u32::from_be_bytes([
        mac[offset],
        mac[offset + 1],
        mac[offset + 2],
        mac[offset + 3],
    ]) & 0x7fff_ffff;
    let code = binary % 10u32.pow(entry.digits);

    Ok(TotpCode {
        code: Zeroizing::new(format!("{code:0width$}", width = entry.digits as usize)),
        // `period` is at most MAX_PERIOD, so the remainder fits in u32.
        seconds_remaining: (period - unix_time_secs % period) as u32,
    })
}

/// Decodes RFC 4648 Base32 as found in TOTP secrets: case-insensitive, with
/// optional `=` padding, and tolerating the spaces and dashes services print for
/// readability.
pub fn decode_base32(input: &str) -> Result<Zeroizing<Vec<u8>>, TotpError> {
    let mut out = Zeroizing::new(Vec::with_capacity(input.len() * 5 / 8));
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    let mut padding_started = false;
    for byte in input.bytes() {
        let value = match byte {
            b' ' | b'-' => continue,
            b'=' => {
                padding_started = true;
                continue;
            }
            _ if padding_started => return Err(TotpError::InvalidSecret),
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return Err(TotpError::InvalidSecret),
        };
        buffer = (buffer << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    if out.is_empty() || out.len() > MAX_SECRET_LEN {
        return Err(TotpError::InvalidSecret);
    }
    Ok(out)
}

/// Decodes percent-encoding. In query values, `+` also means a space.
fn percent_decode(input: &str, plus_is_space: bool) -> Result<String, TotpError> {
    fn hex(byte: u8) -> Option<u8> {
        (byte as char).to_digit(16).map(|digit| digit as u8)
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                let high = bytes.get(index + 1).copied().and_then(hex);
                let low = bytes.get(index + 2).copied().and_then(hex);
                let (Some(high), Some(low)) = (high, low) else {
                    return Err(TotpError::InvalidEncoding);
                };
                out.push(high << 4 | low);
                index += 3;
            }
            b'+' if plus_is_space => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|error| {
        // Wipe the bytes: they may contain part of a secret.
        drop(Zeroizing::new(error.into_bytes()));
        TotpError::InvalidEncoding
    })
}

/// Parses an `otpauth://totp/…` URI, as encoded in the QR codes services show
/// when enabling two-factor authentication.
///
/// The `issuer` parameter takes precedence over an `Issuer:` label prefix.
/// Unknown parameters are ignored; when a parameter repeats, the first one wins.
pub fn parse_otpauth_uri(uri: &str) -> Result<TotpEntry, TotpError> {
    const SCHEME: &str = "otpauth://";
    if uri.len() > MAX_URI_LEN {
        return Err(TotpError::UriTooLong);
    }
    let rest = uri
        .get(..SCHEME.len())
        .filter(|scheme| scheme.eq_ignore_ascii_case(SCHEME))
        .map(|_| &uri[SCHEME.len()..])
        .ok_or(TotpError::NotOtpauth)?;

    let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
    let (kind, label) = path.split_once('/').unwrap_or((path, ""));
    if !kind.eq_ignore_ascii_case("totp") {
        return Err(TotpError::UnsupportedType);
    }

    let label = percent_decode(label, false)?;
    let (label_issuer, account) = match label.split_once(':') {
        Some((issuer, account)) => (issuer.trim(), account.trim()),
        None => ("", label.trim()),
    };

    let mut secret = None;
    let mut issuer = None;
    let mut algorithm = None;
    let mut digits = None;
    let mut period = None;
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let slot = match key.to_ascii_lowercase().as_str() {
            "secret" => &mut secret,
            "issuer" => &mut issuer,
            "algorithm" => &mut algorithm,
            "digits" => &mut digits,
            "period" => &mut period,
            _ => continue,
        };
        if slot.is_none() {
            *slot = Some(Zeroizing::new(percent_decode(value, true)?));
        }
    }

    let secret = decode_base32(&secret.ok_or(TotpError::MissingSecret)?)?;
    let algorithm = match algorithm
        .as_deref()
        .map(|name| name.to_ascii_uppercase())
        .as_deref()
    {
        None | Some("SHA1") => TotpAlgorithm::Sha1,
        Some("SHA256") => TotpAlgorithm::Sha256,
        Some("SHA512") => TotpAlgorithm::Sha512,
        Some(_) => return Err(TotpError::InvalidAlgorithm),
    };
    let digits = match digits {
        None => TotpEntry::DEFAULT_DIGITS,
        Some(digits) => digits.parse().map_err(|_| TotpError::InvalidDigits)?,
    };
    let period = match period {
        None => TotpEntry::DEFAULT_PERIOD,
        Some(period) => period.parse().map_err(|_| TotpError::InvalidPeriod)?,
    };
    let issuer = match issuer {
        Some(issuer) if !issuer.trim().is_empty() => issuer.trim().to_owned(),
        _ => label_issuer.to_owned(),
    };

    let mut entry = TotpEntry::new(issuer, account, secret.to_vec());
    entry.algorithm = algorithm as i32;
    entry.digits = digits;
    entry.period = period;
    validate(&entry)?;
    Ok(entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(secret: &[u8], algorithm: TotpAlgorithm, digits: u32) -> TotpEntry {
        let mut entry = TotpEntry::new("Example", "alice", secret.to_vec());
        entry.algorithm = algorithm as i32;
        entry.digits = digits;
        entry
    }

    /// RFC 6238 appendix B.
    #[test]
    fn matches_the_rfc_6238_test_vectors() {
        let sha1 = entry(b"12345678901234567890", TotpAlgorithm::Sha1, 8);
        let sha256 = entry(
            b"12345678901234567890123456789012",
            TotpAlgorithm::Sha256,
            8,
        );
        let sha512 = entry(
            b"1234567890123456789012345678901234567890123456789012345678901234",
            TotpAlgorithm::Sha512,
            8,
        );
        let vectors: [(u64, &str, &str, &str); 6] = [
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (1_111_111_111, "14050471", "67062674", "99943326"),
            (1_234_567_890, "89005924", "91819424", "93441116"),
            (2_000_000_000, "69279037", "90698825", "38618901"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ];
        for (time, expected_sha1, expected_sha256, expected_sha512) in vectors {
            assert_eq!(
                generate(&sha1, time).unwrap().as_str(),
                expected_sha1,
                "SHA1 at {time}"
            );
            assert_eq!(
                generate(&sha256, time).unwrap().as_str(),
                expected_sha256,
                "SHA256 at {time}"
            );
            assert_eq!(
                generate(&sha512, time).unwrap().as_str(),
                expected_sha512,
                "SHA512 at {time}"
            );
        }
    }

    #[test]
    fn six_digit_codes_are_the_low_digits_and_keep_leading_zeros() {
        let six = entry(b"12345678901234567890", TotpAlgorithm::Sha1, 6);
        assert_eq!(generate(&six, 59).unwrap().as_str(), "287082");
        assert_eq!(generate(&six, 1_111_111_109).unwrap().as_str(), "081804");
        let seven = entry(b"12345678901234567890", TotpAlgorithm::Sha1, 7);
        assert_eq!(generate(&seven, 1_111_111_109).unwrap().as_str(), "7081804");
    }

    #[test]
    fn codes_change_at_period_boundaries() {
        let e = entry(b"12345678901234567890", TotpAlgorithm::Sha1, 6);
        let at = |time| generate(&e, time).unwrap();
        assert_eq!(at(30).as_str(), at(59).as_str());
        assert_ne!(at(59).as_str(), at(60).as_str());
        assert_eq!(at(30).seconds_remaining(), 30);
        assert_eq!(at(31).seconds_remaining(), 29);
        assert_eq!(at(59).seconds_remaining(), 1);
        assert_eq!(at(60).seconds_remaining(), 30);

        let mut slow = e.clone();
        slow.period = 60;
        assert_eq!(
            generate(&slow, 60).unwrap().as_str(),
            generate(&slow, 119).unwrap().as_str()
        );
        assert_eq!(generate(&slow, 61).unwrap().seconds_remaining(), 59);
    }

    #[test]
    fn invalid_entries_are_rejected() {
        let good = entry(b"12345678901234567890", TotpAlgorithm::Sha1, 6);
        assert!(validate(&good).is_ok());

        let with = |change: fn(&mut TotpEntry)| {
            let mut e = good.clone();
            change(&mut e);
            generate(&e, 0).unwrap_err()
        };
        assert_eq!(with(|e| e.secret.clear()), TotpError::InvalidSecret);
        assert_eq!(
            with(|e| e.secret = vec![1; MAX_SECRET_LEN + 1]),
            TotpError::InvalidSecret
        );
        assert_eq!(with(|e| e.algorithm = 3), TotpError::InvalidAlgorithm);
        assert_eq!(with(|e| e.digits = 5), TotpError::InvalidDigits);
        assert_eq!(with(|e| e.digits = 9), TotpError::InvalidDigits);
        assert_eq!(with(|e| e.digits = 0), TotpError::InvalidDigits);
        assert_eq!(with(|e| e.period = 0), TotpError::InvalidPeriod);
        assert_eq!(
            with(|e| e.period = MAX_PERIOD + 1),
            TotpError::InvalidPeriod
        );
    }

    #[test]
    fn code_debug_is_redacted() {
        let code = generate(&entry(b"12345678901234567890", TotpAlgorithm::Sha1, 6), 59).unwrap();
        assert_eq!(format!("{code:?}"), "TotpCode(<redacted>, 1s remaining)");
    }

    #[test]
    fn base32_decodes_rfc_4648_vectors() {
        let cases: [(&str, &[u8]); 6] = [
            ("MY======", b"f"),
            ("MZXQ====", b"fo"),
            ("MZXW6===", b"foo"),
            ("MZXW6YQ=", b"foob"),
            ("MZXW6YTB", b"fooba"),
            ("MZXW6YTBOI======", b"foobar"),
        ];
        for (encoded, decoded) in cases {
            assert_eq!(decode_base32(encoded).unwrap().as_slice(), decoded);
            // Padding is optional and case does not matter.
            let relaxed = encoded.trim_end_matches('=').to_ascii_lowercase();
            assert_eq!(decode_base32(&relaxed).unwrap().as_slice(), decoded);
        }
    }

    #[test]
    fn base32_tolerates_grouping_and_rejects_garbage() {
        assert_eq!(
            decode_base32("GEZD GNBV-gy3t qojq").unwrap().as_slice(),
            b"1234567890"
        );
        for bad in [
            "",
            "====",
            "   ",
            "MZXW1",
            "MZXW8",
            "MZXW!",
            "MZ=XW",
            "日本語",
        ] {
            assert_eq!(
                decode_base32(bad).unwrap_err(),
                TotpError::InvalidSecret,
                "{bad:?}"
            );
        }
        let too_long = "A".repeat((MAX_SECRET_LEN + 1) * 8 / 5 + 8);
        assert_eq!(
            decode_base32(&too_long).unwrap_err(),
            TotpError::InvalidSecret
        );
    }

    #[test]
    fn parses_a_typical_uri() {
        let e = parse_otpauth_uri(
            "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
        )
        .unwrap();
        assert_eq!(e.issuer, "Example");
        assert_eq!(e.account, "alice@example.com");
        assert_eq!(e.secret, b"Hello!\xDE\xAD\xBE\xEF");
        assert_eq!(e.algorithm(), TotpAlgorithm::Sha1);
        assert_eq!((e.digits, e.period), (6, 30));
        assert_eq!(e.login(), None);
    }

    #[test]
    fn parses_all_parameters_and_encodings() {
        let e = parse_otpauth_uri(
            "OTPAUTH://TOTP/ACME%20Co:%20john.doe%40example.com?Secret=jbswy3dpehpk3pxp\
             &ISSUER=ACME+Co%21&algorithm=sha512&digits=8&period=60&image=https%3A%2F%2Fx&unknown",
        )
        .unwrap();
        assert_eq!(e.issuer, "ACME Co!");
        assert_eq!(e.account, "john.doe@example.com");
        assert_eq!(e.algorithm(), TotpAlgorithm::Sha512);
        assert_eq!((e.digits, e.period), (8, 60));

        let e = parse_otpauth_uri(
            "otpauth://totp/%E3%82%B5%E3%83%BC%E3%83%93%E3%82%B9:%E5%A4%AA%E9%83%8E?secret=MZXW6",
        )
        .unwrap();
        assert_eq!(
            (e.issuer.as_str(), e.account.as_str()),
            ("サービス", "太郎")
        );
    }

    #[test]
    fn issuer_falls_back_to_the_label_and_may_be_absent() {
        let e = parse_otpauth_uri("otpauth://totp/Label%20Issuer:bob?secret=MZXW6").unwrap();
        assert_eq!(
            (e.issuer.as_str(), e.account.as_str()),
            ("Label Issuer", "bob")
        );

        let e = parse_otpauth_uri("otpauth://totp/bob?secret=MZXW6").unwrap();
        assert_eq!((e.issuer.as_str(), e.account.as_str()), ("", "bob"));

        let e = parse_otpauth_uri("otpauth://totp/?secret=MZXW6").unwrap();
        assert_eq!((e.issuer.as_str(), e.account.as_str()), ("", ""));

        // The first occurrence of a repeated parameter wins.
        let e = parse_otpauth_uri("otpauth://totp/x?secret=MZXW6&secret=MZXW6YQ&digits=7&digits=8")
            .unwrap();
        assert_eq!(e.secret, b"foo");
        assert_eq!(e.digits, 7);
    }

    #[test]
    fn rejects_malformed_uris() {
        let cases = [
            ("", TotpError::NotOtpauth),
            ("otpauth:/", TotpError::NotOtpauth),
            ("https://example.com/?secret=MZXW6", TotpError::NotOtpauth),
            (
                "otpauth://hotp/x?secret=MZXW6&counter=1",
                TotpError::UnsupportedType,
            ),
            ("otpauth://", TotpError::UnsupportedType),
            ("otpauth://totp/x", TotpError::MissingSecret),
            ("otpauth://totp/x?issuer=y", TotpError::MissingSecret),
            ("otpauth://totp/x?secret=", TotpError::InvalidSecret),
            (
                "otpauth://totp/x?secret=not-base32!",
                TotpError::InvalidSecret,
            ),
            (
                "otpauth://totp/x?secret=MZXW6&algorithm=MD5",
                TotpError::InvalidAlgorithm,
            ),
            (
                "otpauth://totp/x?secret=MZXW6&digits=5",
                TotpError::InvalidDigits,
            ),
            (
                "otpauth://totp/x?secret=MZXW6&digits=six",
                TotpError::InvalidDigits,
            ),
            (
                "otpauth://totp/x?secret=MZXW6&digits=-6",
                TotpError::InvalidDigits,
            ),
            (
                "otpauth://totp/x?secret=MZXW6&period=0",
                TotpError::InvalidPeriod,
            ),
            (
                "otpauth://totp/x?secret=MZXW6&period=99999999999",
                TotpError::InvalidPeriod,
            ),
            (
                "otpauth://totp/a%2?secret=MZXW6",
                TotpError::InvalidEncoding,
            ),
            (
                "otpauth://totp/a%zz?secret=MZXW6",
                TotpError::InvalidEncoding,
            ),
            (
                "otpauth://totp/%FF%FE?secret=MZXW6",
                TotpError::InvalidEncoding,
            ),
            (
                "otpauth://totp/x?secret=MZXW6&issuer=%C3",
                TotpError::InvalidEncoding,
            ),
        ];
        for (uri, expected) in cases {
            assert_eq!(parse_otpauth_uri(uri).unwrap_err(), expected, "{uri:?}");
        }
        let long = format!("otpauth://totp/{}?secret=MZXW6", "a".repeat(MAX_URI_LEN));
        assert_eq!(parse_otpauth_uri(&long).unwrap_err(), TotpError::UriTooLong);
        // A multi-byte character straddling the scheme length must not panic.
        assert_eq!(
            parse_otpauth_uri("otpauth:/日本").unwrap_err(),
            TotpError::NotOtpauth
        );
    }

    #[test]
    fn a_parsed_uri_generates_the_expected_code() {
        // The RFC 6238 SHA-1 secret "12345678901234567890" in Base32.
        let e = parse_otpauth_uri(
            "otpauth://totp/RFC:test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8",
        )
        .unwrap();
        assert_eq!(generate(&e, 59).unwrap().as_str(), "94287082");
    }
}

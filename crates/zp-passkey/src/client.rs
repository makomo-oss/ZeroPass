//! The part of the WebAuthn client that ZeroPass plays itself
//! (`docs/spec/passkey.md` §7, §8): which relying party a page may use, and
//! the client data the signature covers.
//!
//! The origin is the one the browser reported for the frame that asked (the
//! extension takes it from the browser, never from the page), so the client
//! data commits to the page the user is really on: a phishing page gets a
//! signature that names the phishing page, and no credential of the site it
//! imitates at all.

use zp_origin::Origin;

use crate::PasskeyError;

/// The longest challenge accepted. WebAuthn asks relying parties for at
/// least 16 random bytes; nothing needs more than this.
pub const MAX_CHALLENGE_LEN: usize = 1024;

/// Which ceremony the client data is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ceremony {
    /// `navigator.credentials.create`: a new credential.
    Create,
    /// `navigator.credentials.get`: an assertion.
    Get,
}

impl Ceremony {
    /// The `type` member of the client data.
    pub const fn client_data_type(self) -> &'static str {
        match self {
            Ceremony::Create => "webauthn.create",
            Ceremony::Get => "webauthn.get",
        }
    }
}

/// The page that asks, as the browser reported it: the origin of the frame,
/// and the origin of the tab's top frame when that is another one.
#[derive(Debug, Clone)]
pub struct Caller {
    origin: Origin,
    /// The top frame's origin, if the frame is not the top frame's origin.
    top: Option<Origin>,
}

impl Caller {
    /// The frame `origin`, in the tab whose top frame is `top` (empty or the
    /// same: the frame is the top). A frame of another site than the top
    /// frame may not use passkeys through ZeroPass, as it may not fill
    /// logins (`docs/spec/extension.md` §7).
    pub fn new(origin: &str, top: &str) -> Result<Self, PasskeyError> {
        let origin = Origin::parse(origin).map_err(|_| PasskeyError::BadOrigin)?;
        let top = if top.is_empty() {
            None
        } else {
            let top = Origin::parse(top).map_err(|_| PasskeyError::BadOrigin)?;
            if !origin.same_site(&top) {
                return Err(PasskeyError::CrossSite);
            }
            (top != origin).then_some(top)
        };
        Ok(Self { origin, top })
    }

    /// The relying party identifier to use for `requested` (the request's
    /// `rp.id` or `rpId`; empty: none given), if this page may.
    pub fn relying_party(&self, requested: &str) -> Result<String, PasskeyError> {
        self.origin
            .relying_party_id(requested.trim())
            .ok_or(PasskeyError::BadRelyingParty)
    }

    /// The client data JSON of a ceremony with `challenge`.
    pub fn client_data(
        &self,
        ceremony: Ceremony,
        challenge: &[u8],
    ) -> Result<Vec<u8>, PasskeyError> {
        if challenge.is_empty() || challenge.len() > MAX_CHALLENGE_LEN {
            return Err(PasskeyError::Invalid("the challenge is 1 to 1024 bytes"));
        }
        let top = self.top.as_ref().map(Origin::to_string);
        Ok(client_data_json(
            ceremony,
            challenge,
            &self.origin.to_string(),
            top.as_deref(),
        ))
    }
}

/// The client data JSON (WebAuthn §5.8.1), in the serialisation of §5.8.1.1:
/// `type`, `challenge`, `origin`, `crossOrigin`, and `topOrigin` when the
/// frame is not the top frame's origin.
pub fn client_data_json(
    ceremony: Ceremony,
    challenge: &[u8],
    origin: &str,
    top_origin: Option<&str>,
) -> Vec<u8> {
    let mut json = String::from("{\"type\":");
    json_string(&mut json, ceremony.client_data_type());
    json.push_str(",\"challenge\":");
    json_string(&mut json, &base64url(challenge));
    json.push_str(",\"origin\":");
    json_string(&mut json, origin);
    json.push_str(",\"crossOrigin\":");
    match top_origin {
        None => json.push_str("false"),
        Some(top) => {
            json.push_str("true,\"topOrigin\":");
            json_string(&mut json, top);
        }
    }
    json.push('}');
    json.into_bytes()
}

/// `CCDToString` (WebAuthn §5.8.1.2): a JSON string with `"` and `\`
/// escaped, and control characters as `\uXXXX`.
fn json_string(out: &mut String, value: &str) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Base64url without padding (RFC 4648 §5), as WebAuthn encodes challenges.
pub fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |n, (index, byte)| {
            n | u32::from(*byte) << (16 - 8 * index)
        });
        // One more symbol than whole bytes in the chunk.
        for index in 0..=chunk.len() {
            out.push(char::from(
                ALPHABET[(n >> (18 - 6 * index)) as usize & 0x3f],
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_matches_rfc_4648() {
        // RFC 4648 §10, without padding.
        for (input, output) in [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64url(input.as_bytes()), output);
        }
        assert_eq!(base64url(&[0xfb, 0xff, 0xbf]), "-_-_");
    }

    #[test]
    fn client_data_is_serialised_as_webauthn_specifies() {
        let json = client_data_json(Ceremony::Get, b"\x01\x02", "https://example.org", None);
        assert_eq!(
            String::from_utf8(json).unwrap(),
            r#"{"type":"webauthn.get","challenge":"AQI","origin":"https://example.org","crossOrigin":false}"#
        );
        let json = client_data_json(
            Ceremony::Create,
            b"\x01",
            "https://login.example.org",
            Some("https://example.org"),
        );
        assert_eq!(
            String::from_utf8(json).unwrap(),
            r#"{"type":"webauthn.create","challenge":"AQ","origin":"https://login.example.org","crossOrigin":true,"topOrigin":"https://example.org"}"#
        );
        let mut escaped = String::new();
        json_string(&mut escaped, "a\"b\\c\u{1}é");
        assert_eq!(escaped, r#""a\"b\\c\u0001é""#);
    }

    #[test]
    fn a_frame_of_the_same_site_is_cross_origin_and_another_site_is_refused() {
        let top = Caller::new("https://example.org", "").unwrap();
        let data = top.client_data(Ceremony::Get, b"challenge").unwrap();
        assert!(
            String::from_utf8(data)
                .unwrap()
                .ends_with(r#""origin":"https://example.org","crossOrigin":false}"#)
        );
        let same = Caller::new("https://example.org", "https://example.org").unwrap();
        assert!(same.top.is_none());
        let framed = Caller::new("https://login.example.org", "https://www.example.org").unwrap();
        let data = String::from_utf8(framed.client_data(Ceremony::Get, b"x").unwrap()).unwrap();
        assert!(
            data.ends_with(r#""crossOrigin":true,"topOrigin":"https://www.example.org"}"#),
            "{data}"
        );
        assert!(matches!(
            Caller::new("https://example.org", "https://evil.example"),
            Err(PasskeyError::CrossSite)
        ));
        for bad in [
            "example.org",
            "ftp://example.org",
            "https://example.org/path",
        ] {
            assert!(
                matches!(Caller::new(bad, ""), Err(PasskeyError::BadOrigin)),
                "{bad}"
            );
        }
    }

    #[test]
    fn the_relying_party_and_the_challenge_are_checked() {
        let caller = Caller::new("https://login.example.org", "").unwrap();
        assert_eq!(caller.relying_party("").unwrap(), "login.example.org");
        assert_eq!(caller.relying_party("example.org").unwrap(), "example.org");
        assert!(matches!(
            caller.relying_party("org"),
            Err(PasskeyError::BadRelyingParty)
        ));
        assert!(matches!(
            caller.relying_party("example.com"),
            Err(PasskeyError::BadRelyingParty)
        ));
        let insecure = Caller::new("http://example.org", "").unwrap();
        assert!(matches!(
            insecure.relying_party(""),
            Err(PasskeyError::BadRelyingParty)
        ));
        for challenge in [&[][..], &[0; MAX_CHALLENGE_LEN + 1][..]] {
            assert!(matches!(
                caller.client_data(Ceremony::Create, challenge),
                Err(PasskeyError::Invalid(_))
            ));
        }
    }
}

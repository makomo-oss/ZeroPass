//! Which logins belong to a web page (`docs/spec/extension.md` §5).
//!
//! The browser extension tells the vault daemon the origin of the page it is
//! about to fill. The daemon, not the extension, decides which logins match:
//! the same scheme, host and port ([`Match::Exact`]), or the same registrable
//! domain under the public suffix list, private section included
//! ([`Match::Site`]). Hosts are compared in their ASCII (Punycode) form, so a
//! look-alike domain never matches the domain it imitates.
//!
//! Nothing here reaches the network: the public suffix list is compiled in.

use std::net::IpAddr;

use url::{Host, Url};

/// The origin of a web page: what a browser reports as `URL.origin`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    https: bool,
    host: String,
    port: u16,
}

/// Why an origin was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OriginError {
    /// Not of the form `scheme://host[:port]`.
    Malformed,
    /// A scheme other than `https` or `http`.
    Scheme,
}

/// Why a WebAuthn relying party identifier was refused for an origin
/// (`docs/spec/passkey.md` §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpIdError {
    /// Passkeys require `https` or a loopback `http` origin.
    InsecureOrigin,
    /// The relying party identifier is not a valid host name.
    Malformed,
    /// The relying party identifier is not a valid domain for this origin
    /// (different site, or a public suffix itself).
    NotAllowed,
}

impl core::fmt::Display for RpIdError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RpIdError::InsecureOrigin => {
                f.write_str("passkeys require an https origin (or http on localhost)")
            }
            RpIdError::Malformed => {
                f.write_str("the relying party identifier is not a valid host name")
            }
            RpIdError::NotAllowed => {
                f.write_str("the relying party identifier does not match this origin")
            }
        }
    }
}

impl std::error::Error for RpIdError {}

impl core::fmt::Display for OriginError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            OriginError::Malformed => {
                f.write_str("the origin is not of the form scheme://host[:port]")
            }
            OriginError::Scheme => f.write_str("only https and http pages can be filled"),
        }
    }
}

impl std::error::Error for OriginError {}

/// How well a login matches a page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Match {
    /// The same registrable domain, another host.
    Site,
    /// The same scheme (or an upgrade from `http` to `https`), host and port.
    Exact,
}

impl Match {
    /// The word for it in the extension's messages.
    pub fn name(self) -> &'static str {
        match self {
            Match::Exact => "exact",
            Match::Site => "site",
        }
    }
}

impl Origin {
    /// Reads a page's origin as the browser gives it: `scheme://host[:port]`,
    /// nothing after it (a trailing `/` is tolerated).
    pub fn parse(text: &str) -> Result<Self, OriginError> {
        let url = Url::parse(text).map_err(|_| OriginError::Malformed)?;
        let https = match url.scheme() {
            "https" => true,
            "http" => false,
            _ => return Err(OriginError::Scheme),
        };
        let bare = url.path() == "/" && url.query().is_none() && url.fragment().is_none();
        if !bare || !url.username().is_empty() || url.password().is_some() {
            return Err(OriginError::Malformed);
        }
        Self::of(&url, https).ok_or(OriginError::Malformed)
    }

    fn of(url: &Url, https: bool) -> Option<Self> {
        let host = match url.host()? {
            Host::Domain(domain) => domain.trim_end_matches('.').to_ascii_lowercase(),
            Host::Ipv4(address) => address.to_string(),
            Host::Ipv6(address) => format!("[{address}]"),
        };
        if host.is_empty() {
            return None;
        }
        Some(Self {
            https,
            host,
            port: url.port_or_known_default()?,
        })
    }

    /// The host, in ASCII.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The registrable domain of the host (eTLD+1), if the host is a domain
    /// name below a public suffix.
    pub fn site(&self) -> Option<&str> {
        if !self.is_domain() {
            return None;
        }
        psl::domain_str(&self.host)
    }

    /// Whether the host is a domain name with a dot (not an IP address, not
    /// `localhost` or another single label).
    fn is_domain(&self) -> bool {
        let bare = self.host.trim_start_matches('[').trim_end_matches(']');
        self.host.contains('.') && bare.parse::<IpAddr>().is_err()
    }

    /// Whether `other` belongs to the same site as this origin: the same
    /// registrable domain, or the same host where there is none. For the
    /// frames of one page (`docs/spec/extension.md` §7).
    pub fn same_site(&self, other: &Origin) -> bool {
        match (self.site(), other.site()) {
            (Some(mine), Some(theirs)) => mine == theirs,
            _ => self.host == other.host,
        }
    }

    /// Whether passkeys may be created or used on this origin: `https`, or
    /// `http` on a loopback host (`localhost`, `127.0.0.1`, `[::1]`) for local
    /// development and testing (`docs/spec/passkey.md` §3).
    pub fn is_passkey_origin(&self) -> bool {
        if self.https {
            return true;
        }
        matches!(self.host.as_str(), "localhost" | "127.0.0.1" | "[::1]")
            || self.host.ends_with(".localhost")
    }

    /// Validates a WebAuthn relying party identifier (`rpId`) against this
    /// origin and returns the canonical ASCII lower-case RP ID
    /// (`docs/spec/passkey.md` §3).
    ///
    /// When `rp_id` is `None` or empty, this origin's host is used.
    pub fn validate_rp_id(&self, rp_id: Option<&str>) -> Result<String, RpIdError> {
        if !self.is_passkey_origin() {
            return Err(RpIdError::InsecureOrigin);
        }
        let Some(raw) = rp_id.filter(|value| !value.is_empty()) else {
            return Ok(self.host.clone());
        };
        let normalized = parse_rp_id(raw)?;
        if normalized == self.host {
            return Ok(normalized);
        }
        if !self.is_domain() {
            return Err(RpIdError::NotAllowed);
        }
        let suffix = format!(".{normalized}");
        if !self.host.ends_with(&suffix) {
            return Err(RpIdError::NotAllowed);
        }
        // Reject public suffixes (such as `com`, `co.uk`, `github.io`).
        if psl::domain_str(&normalized).is_none() {
            return Err(RpIdError::NotAllowed);
        }
        Ok(normalized)
    }

    /// How well the URL a login was saved with matches this page, if at all.
    /// A URL without a scheme is taken as `https`.
    pub fn matches(&self, saved: &str) -> Option<Match> {
        let saved = saved.trim();
        if saved.is_empty() {
            return None;
        }
        let with_scheme = if saved.contains("://") {
            saved.to_owned()
        } else {
            format!("https://{saved}")
        };
        let url = Url::parse(&with_scheme).ok()?;
        let https = match url.scheme() {
            "https" => true,
            "http" => false,
            _ => return None,
        };
        let login = Self::of(&url, https)?;
        // A login saved for https is never filled into an http page; one
        // saved for http may be filled into the https page of its host.
        if login.https && !self.https {
            return None;
        }
        let ports_agree = if login.https == self.https {
            login.port == self.port
        } else {
            // An upgrade from http to https: the default ports of both.
            login.port == 80 && self.port == 443
        };
        if !ports_agree {
            return None;
        }
        if login.host == self.host {
            return Some(Match::Exact);
        }
        match (self.site(), login.site()) {
            (Some(page), Some(saved)) if page == saved => Some(Match::Site),
            _ => None,
        }
    }

    /// The best match among the URLs of one login.
    pub fn best_match<'a>(&self, urls: impl IntoIterator<Item = &'a str>) -> Option<Match> {
        urls.into_iter().filter_map(|url| self.matches(url)).max()
    }
}

impl core::fmt::Display for Origin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let scheme = if self.https { "https" } else { "http" };
        let default = if self.https { 443 } else { 80 };
        if self.port == default {
            write!(f, "{scheme}://{}", self.host)
        } else {
            write!(f, "{scheme}://{}:{}", self.host, self.port)
        }
    }
}

/// Parses and validates a bare WebAuthn RP ID (ASCII host name without scheme,
/// port, path, or trailing dot).
fn parse_rp_id(raw: &str) -> Result<String, RpIdError> {
    if raw.is_empty()
        || !raw.is_ascii()
        || raw.starts_with('.')
        || raw.ends_with('.')
        || raw.contains("..")
        || raw.bytes().any(|b| {
            b.is_ascii_control()
                || b.is_ascii_whitespace()
                || matches!(b, b'/' | b'?' | b'#' | b'@')
        })
    {
        return Err(RpIdError::Malformed);
    }
    let url = Url::parse(&format!("https://{raw}")).map_err(|_| RpIdError::Malformed)?;
    if url.port().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(RpIdError::Malformed);
    }
    let host = match url.host().ok_or(RpIdError::Malformed)? {
        Host::Domain(domain) => domain.to_ascii_lowercase(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => format!("[{address}]"),
    };
    // Require exact canonical match (rejects shorthand IPv4 like `127.1`, etc.).
    if host != raw.to_ascii_lowercase() {
        return Err(RpIdError::Malformed);
    }
    Ok(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(origin: &str) -> Origin {
        Origin::parse(origin).unwrap()
    }

    #[test]
    fn only_bare_web_origins_are_accepted() {
        assert_eq!(page("https://Example.COM").host(), "example.com");
        assert_eq!(
            page("https://example.com/").to_string(),
            "https://example.com"
        );
        assert_eq!(
            page("http://example.com:8080").to_string(),
            "http://example.com:8080"
        );
        for bad in [
            "",
            "example.com",
            "https://example.com/login",
            "https://example.com/?a=1",
            "https://user@example.com",
            "https://",
        ] {
            assert_eq!(Origin::parse(bad), Err(OriginError::Malformed), "{bad:?}");
        }
        for scheme in [
            "ftp://example.com",
            "chrome-extension://abc",
            "file:///C:/x",
            "javascript:alert(1)",
        ] {
            assert!(Origin::parse(scheme).is_err(), "{scheme:?}");
        }
    }

    #[test]
    fn the_same_host_matches_exactly() {
        let bank = page("https://bank.example.com");
        assert_eq!(
            bank.matches("https://bank.example.com/login?next=/"),
            Some(Match::Exact)
        );
        assert_eq!(bank.matches("bank.example.com"), Some(Match::Exact));
        assert_eq!(bank.matches("HTTPS://BANK.EXAMPLE.COM"), Some(Match::Exact));
        assert_eq!(
            bank.matches("https://bank.example.com:443/"),
            Some(Match::Exact)
        );
    }

    #[test]
    fn another_host_of_the_same_registrable_domain_matches_the_site() {
        let login = page("https://login.example.co.uk");
        assert_eq!(
            login.matches("https://www.example.co.uk"),
            Some(Match::Site)
        );
        assert_eq!(login.matches("https://example.co.uk"), Some(Match::Site));
        // co.uk is a public suffix: another registrable domain.
        assert_eq!(login.matches("https://other.co.uk"), None);
    }

    #[test]
    fn look_alike_and_embedded_domains_do_not_match() {
        let real = page("https://example.com");
        // A Cyrillic "е" in place of the first Latin "e": in Punycode,
        // another domain.
        let unicode = "https://\u{0435}xample.com";
        let ascii = Url::parse(unicode).unwrap();
        let homograph = page(&format!("https://{}", ascii.host_str().unwrap()));
        assert!(homograph.host().starts_with("xn--"), "{}", homograph.host());
        assert_eq!(homograph.matches("https://example.com"), None);
        assert_eq!(real.matches(unicode), None);
        // The Unicode form of its own domain does match it.
        assert_eq!(homograph.matches(unicode), Some(Match::Exact));
        for evil in [
            "https://example.com.evil.net",
            "https://examp1e.com",
            "https://evil-example.com",
            "https://example.co",
        ] {
            assert_eq!(page(evil).matches("https://example.com"), None, "{evil}");
        }
    }

    #[test]
    fn https_is_never_downgraded_but_http_may_be_upgraded() {
        assert_eq!(
            page("http://example.com").matches("https://example.com"),
            None
        );
        assert_eq!(
            page("http://www.example.com").matches("https://example.com"),
            None
        );
        assert_eq!(
            page("https://example.com").matches("http://example.com"),
            Some(Match::Exact)
        );
        assert_eq!(
            page("http://example.com").matches("http://example.com"),
            Some(Match::Exact)
        );
    }

    #[test]
    fn ports_must_agree() {
        assert_eq!(
            page("https://example.com:8443").matches("https://example.com"),
            None
        );
        assert_eq!(
            page("https://example.com:8443").matches("https://example.com:8443/x"),
            Some(Match::Exact)
        );
        assert_eq!(
            page("https://example.com").matches("https://example.com:8443"),
            None
        );
    }

    #[test]
    fn users_of_shared_hosting_are_different_sites() {
        let alice = page("https://alice.github.io");
        assert_eq!(alice.matches("https://bob.github.io"), None);
        assert_eq!(
            alice.matches("https://alice.github.io/repo"),
            Some(Match::Exact)
        );
        // A public suffix itself is no site.
        assert_eq!(page("https://github.io").site(), None);
        assert_eq!(
            page("https://github.io").matches("https://alice.github.io"),
            None
        );
        assert_eq!(
            page("https://x.blogspot.com").matches("https://y.blogspot.com"),
            None
        );
    }

    #[test]
    fn addresses_and_single_labels_match_exactly_only() {
        assert_eq!(
            page("http://192.168.1.1").matches("http://192.168.1.1/admin"),
            Some(Match::Exact)
        );
        assert_eq!(
            page("http://192.168.1.1").matches("http://192.168.1.2"),
            None
        );
        assert_eq!(
            page("http://localhost:3000").matches("http://localhost:3000"),
            Some(Match::Exact)
        );
        assert_eq!(page("http://router").matches("http://other"), None);
        assert_eq!(
            page("https://[::1]").matches("https://[::1]/"),
            Some(Match::Exact)
        );
        assert_eq!(page("http://192.168.1.1").site(), None);
    }

    #[test]
    fn unreadable_saved_urls_match_nothing() {
        let example = page("https://example.com");
        for bad in [
            "",
            "   ",
            "ftp://example.com",
            "https://",
            "not a url at all",
        ] {
            assert_eq!(example.matches(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn the_best_of_several_urls_counts() {
        let login = page("https://login.example.com");
        assert_eq!(
            login.best_match([
                "https://other.org",
                "https://www.example.com",
                "https://login.example.com"
            ]),
            Some(Match::Exact)
        );
        assert_eq!(
            login.best_match(["https://www.example.com"]),
            Some(Match::Site)
        );
        assert_eq!(login.best_match(["https://other.org"]), None);
    }

    #[test]
    fn frames_of_one_site_are_recognised() {
        let top = page("https://www.example.com");
        assert!(top.same_site(&page("https://login.example.com")));
        assert!(!top.same_site(&page("https://evil.net")));
        assert!(!page("https://alice.github.io").same_site(&page("https://bob.github.io")));
        assert!(page("http://localhost:1").same_site(&page("http://localhost:2")));
    }

    #[test]
    fn passkey_rp_id_matches_origin_or_registrable_ancestor() {
        let login = page("https://login.example.com");
        assert_eq!(login.validate_rp_id(None), Ok("login.example.com".into()));
        assert_eq!(
            login.validate_rp_id(Some("")),
            Ok("login.example.com".into())
        );
        assert_eq!(
            login.validate_rp_id(Some("login.example.com")),
            Ok("login.example.com".into())
        );
        assert_eq!(
            login.validate_rp_id(Some("Example.COM")),
            Ok("example.com".into())
        );
        assert_eq!(
            page("https://a.b.example.co.uk").validate_rp_id(Some("example.co.uk")),
            Ok("example.co.uk".into())
        );
        assert_eq!(
            page("https://sub.alice.github.io").validate_rp_id(Some("alice.github.io")),
            Ok("alice.github.io".into())
        );
        assert_eq!(
            page("http://localhost:3000").validate_rp_id(Some("localhost")),
            Ok("localhost".into())
        );
        assert_eq!(
            page("http://127.0.0.1:8080").validate_rp_id(None),
            Ok("127.0.0.1".into())
        );
        assert_eq!(
            page("http://[::1]:8080").validate_rp_id(Some("[::1]")),
            Ok("[::1]".into())
        );
    }

    #[test]
    fn passkey_rp_id_rejects_insecure_cross_site_public_suffix_and_malformed() {
        // Non-loopback http is forbidden.
        assert_eq!(
            page("http://example.com").validate_rp_id(Some("example.com")),
            Err(RpIdError::InsecureOrigin)
        );
        assert_eq!(
            page("http://192.168.1.1").validate_rp_id(None),
            Err(RpIdError::InsecureOrigin)
        );

        // Public suffixes and unrelated/sibling/child domains are refused.
        let login = page("https://login.example.com");
        for disallowed in [
            "com",
            "other.com",
            "notexample.com",
            "sub.login.example.com",
            "www.example.com",
        ] {
            assert_eq!(
                login.validate_rp_id(Some(disallowed)),
                Err(RpIdError::NotAllowed),
                "{disallowed}"
            );
        }
        assert_eq!(
            page("https://app.example.co.uk").validate_rp_id(Some("co.uk")),
            Err(RpIdError::NotAllowed)
        );
        assert_eq!(
            page("https://alice.github.io").validate_rp_id(Some("github.io")),
            Err(RpIdError::NotAllowed)
        );
        assert_eq!(
            page("https://alice.github.io").validate_rp_id(Some("bob.github.io")),
            Err(RpIdError::NotAllowed)
        );
        assert_eq!(
            page("https://192.168.1.1").validate_rp_id(Some("192.168.1.2")),
            Err(RpIdError::NotAllowed)
        );

        // Malformed RP IDs: scheme, port, path, trailing dot, unicode, spaces.
        for bad in [
            "https://example.com",
            "example.com:443",
            "example.com/path",
            "example.com.",
            ".example.com",
            "a..example.com",
            "user@example.com",
            "example.com ",
            "\u{0435}xample.com",
            "127.1",
        ] {
            assert_eq!(
                login.validate_rp_id(Some(bad)),
                Err(RpIdError::Malformed),
                "{bad:?}"
            );
        }
    }
}

//! Reads what other password managers export, into what ZeroPass keeps
//! (`docs/spec/export.md` §4).
//!
//! | Source | File |
//! |---|---|
//! | Chrome, Edge (and other Chromium browsers) | "Export passwords": CSV `name,url,username,password[,note]` |
//! | Firefox | "Export logins": CSV `url,username,password,httpRealm,...` |
//! | Bitwarden | "Export vault" as `.json` (unencrypted) or `.csv` |
//! | 1Password | "Export" as `.csv` |
//!
//! The format is recognised from the file. Logins keep their URLs, notes and
//! one-time-code setup keys (as `otpauth://` addresses); secure notes keep
//! their text; anything else (cards, identities) is counted as skipped. The
//! files hold every password in the clear: they are read here, in the user
//! interface's process, and their contents are wiped when dropped.

use std::fmt::Write as _;

use serde::Deserialize;
use zeroize::Zeroize;

/// A file format this crate reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Chrome, Edge and other Chromium browsers.
    ChromeCsv,
    /// Firefox.
    FirefoxCsv,
    /// Bitwarden, unencrypted JSON.
    BitwardenJson,
    /// Bitwarden, CSV.
    BitwardenCsv,
    /// 1Password, CSV.
    OnePasswordCsv,
}

impl Format {
    /// The name to show for it.
    pub fn name(self) -> &'static str {
        match self {
            Format::ChromeCsv => "Chrome / Edge (CSV)",
            Format::FirefoxCsv => "Firefox (CSV)",
            Format::BitwardenJson => "Bitwarden (JSON)",
            Format::BitwardenCsv => "Bitwarden (CSV)",
            Format::OnePasswordCsv => "1Password (CSV)",
        }
    }
}

/// A login read from a file.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ImportedLogin {
    /// Its title.
    pub title: String,
    /// The user name.
    pub username: String,
    /// The password.
    pub password: String,
    /// Where it is used.
    pub urls: Vec<String>,
    /// Free text.
    pub notes: String,
    /// The one-time-code setup key, as an `otpauth://` address.
    pub totp: Option<String>,
}

impl Drop for ImportedLogin {
    fn drop(&mut self) {
        self.password.zeroize();
        self.notes.zeroize();
        if let Some(totp) = self.totp.as_mut() {
            totp.zeroize();
        }
    }
}

/// A secure note read from a file.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ImportedNote {
    /// Its title.
    pub title: String,
    /// Its text.
    pub body: String,
}

impl Drop for ImportedNote {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}

/// What a file held.
#[derive(Debug)]
pub struct Imported {
    /// The format it was in.
    pub format: Format,
    /// Its logins.
    pub logins: Vec<ImportedLogin>,
    /// Its secure notes.
    pub notes: Vec<ImportedNote>,
    /// Entries of kinds ZeroPass does not keep (cards, identities), and rows
    /// without anything to keep.
    pub skipped: usize,
}

/// Why a file could not be read.
#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    /// Neither a known CSV header nor a known JSON export.
    #[error(
        "the file is not an export ZeroPass can read (Chrome, Edge, Firefox, Bitwarden, 1Password)"
    )]
    UnknownFormat,
    /// A Bitwarden export protected by Bitwarden's own encryption.
    #[error(
        "this Bitwarden export is encrypted: export the vault again as unencrypted JSON or CSV"
    )]
    EncryptedBitwarden,
    /// The file is not valid UTF-8 text.
    #[error("the file is not text")]
    NotText,
    /// The CSV could not be read.
    #[error("the CSV file is malformed: {0}")]
    Csv(String),
    /// The JSON could not be read.
    #[error("the JSON file is malformed: {0}")]
    Json(String),
}

/// Reads a file, recognising its format.
pub fn read(bytes: &[u8]) -> Result<Imported, ImportError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ImportError::NotText)?;
    let text = text.trim_start_matches('\u{feff}');
    if text.trim_start().starts_with('{') {
        return bitwarden_json(text);
    }
    read_csv(text)
}

/// An `otpauth://` address for a setup key as a manager stores it: either
/// an address already, or a Base32 secret. `None` for what is neither
/// (Steam's codes, for one).
pub fn totp_address(value: &str, issuer: &str, account: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if value.to_ascii_lowercase().starts_with("otpauth://") {
        return Some(value.to_owned());
    }
    let secret: String = value
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let base32 = !secret.is_empty()
        && secret
            .trim_end_matches('=')
            .chars()
            .all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c));
    if !base32 {
        return None;
    }
    let label = if account.is_empty() {
        encode(issuer)
    } else {
        format!("{}:{}", encode(issuer), encode(account))
    };
    Some(format!(
        "otpauth://totp/{label}?secret={secret}&issuer={}",
        encode(issuer)
    ))
}

/// Percent-encoding for the parts of an `otpauth://` address.
fn encode(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'@') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

// --- Bitwarden JSON -------------------------------------------------------

#[derive(Deserialize)]
struct BitwardenExport {
    #[serde(default)]
    encrypted: bool,
    #[serde(default)]
    items: Vec<BitwardenItem>,
}

#[derive(Deserialize)]
struct BitwardenItem {
    #[serde(rename = "type")]
    kind: u32,
    #[serde(default)]
    name: String,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    login: Option<BitwardenLogin>,
}

#[derive(Deserialize)]
struct BitwardenLogin {
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    totp: Option<String>,
    #[serde(default)]
    uris: Option<Vec<BitwardenUri>>,
}

#[derive(Deserialize)]
struct BitwardenUri {
    #[serde(default)]
    uri: Option<String>,
}

fn bitwarden_json(text: &str) -> Result<Imported, ImportError> {
    let export: BitwardenExport =
        serde_json::from_str(text).map_err(|error| ImportError::Json(error.to_string()))?;
    if export.encrypted {
        return Err(ImportError::EncryptedBitwarden);
    }
    let mut imported = Imported {
        format: Format::BitwardenJson,
        logins: Vec::new(),
        notes: Vec::new(),
        skipped: 0,
    };
    for item in export.items {
        let notes = item.notes.unwrap_or_default();
        match (item.kind, item.login) {
            (1, Some(login)) => {
                let username = login.username.unwrap_or_default();
                let totp = login
                    .totp
                    .as_deref()
                    .and_then(|value| totp_address(value, &item.name, &username));
                imported.logins.push(ImportedLogin {
                    urls: login
                        .uris
                        .unwrap_or_default()
                        .into_iter()
                        .filter_map(|uri| uri.uri)
                        .filter(|uri| !uri.trim().is_empty())
                        .collect(),
                    password: login.password.unwrap_or_default(),
                    title: item.name,
                    username,
                    notes,
                    totp,
                });
            }
            (2, _) => imported.notes.push(ImportedNote {
                title: item.name,
                body: notes,
            }),
            _ => imported.skipped += 1,
        }
    }
    Ok(imported)
}

// --- CSV ------------------------------------------------------------------

/// The columns of a CSV file, by their lower-cased names.
struct Columns(Vec<String>);

impl Columns {
    fn has(&self, name: &str) -> bool {
        self.0.iter().any(|column| column == name)
    }

    fn index(&self, names: &[&str]) -> Option<usize> {
        names
            .iter()
            .find_map(|name| self.0.iter().position(|column| column == name))
    }
}

fn read_csv(text: &str) -> Result<Imported, ImportError> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(text.as_bytes());
    let headers = reader
        .headers()
        .map_err(|error| ImportError::Csv(error.to_string()))?;
    let columns = Columns(
        headers
            .iter()
            .map(|name| name.trim().to_lowercase())
            .collect(),
    );
    let format = if columns.has("login_password") && columns.has("type") {
        Format::BitwardenCsv
    } else if columns.has("httprealm") || columns.has("formactionorigin") {
        Format::FirefoxCsv
    } else if columns.has("name") && columns.has("url") && columns.has("password") {
        Format::ChromeCsv
    } else if columns.has("title") && columns.has("password") {
        Format::OnePasswordCsv
    } else {
        return Err(ImportError::UnknownFormat);
    };

    let pick = |names: &[&str]| columns.index(names);
    let (title, url, username, password, notes, otp, kind) = match format {
        Format::ChromeCsv => (
            pick(&["name"]),
            pick(&["url"]),
            pick(&["username"]),
            pick(&["password"]),
            pick(&["note", "notes"]),
            None,
            None,
        ),
        Format::FirefoxCsv => (
            None,
            pick(&["url"]),
            pick(&["username"]),
            pick(&["password"]),
            None,
            None,
            None,
        ),
        Format::BitwardenCsv => (
            pick(&["name"]),
            pick(&["login_uri"]),
            pick(&["login_username"]),
            pick(&["login_password"]),
            pick(&["notes"]),
            pick(&["login_totp"]),
            pick(&["type"]),
        ),
        Format::OnePasswordCsv => (
            pick(&["title"]),
            pick(&["url", "website", "urls", "login url"]),
            pick(&["username", "login username"]),
            pick(&["password", "login password"]),
            pick(&["notes", "notesplain"]),
            pick(&["otpauth", "one-time password", "otp", "totp"]),
            pick(&["type", "category"]),
        ),
        Format::BitwardenJson => unreachable!("not a CSV format"),
    };

    let mut imported = Imported {
        format,
        logins: Vec::new(),
        notes: Vec::new(),
        skipped: 0,
    };
    for record in reader.records() {
        let mut record = record.map_err(|error| ImportError::Csv(error.to_string()))?;
        let field = |index: Option<usize>| {
            index
                .and_then(|index| record.get(index))
                .unwrap_or("")
                .to_owned()
        };
        let kind = field(kind).to_lowercase();
        let mut row_title = field(title);
        let row_url = field(url);
        let row_username = field(username);
        let row_password = field(password);
        let row_notes = field(notes);
        let row_otp = field(otp);
        // The plaintext row is not kept beyond its fields.
        record.clear();

        let is_note = kind == "note" || kind == "secure note" || kind == "securenote";
        if is_note {
            imported.notes.push(ImportedNote {
                title: row_title,
                body: row_notes,
            });
            continue;
        }
        if !kind.is_empty() && kind != "login" && format == Format::BitwardenCsv {
            imported.skipped += 1;
            continue;
        }
        if row_password.is_empty() && row_username.is_empty() {
            imported.skipped += 1;
            continue;
        }
        if row_title.is_empty() {
            row_title = host_of(&row_url).unwrap_or_else(|| "(no title)".to_owned());
        }
        let urls = match format {
            // Bitwarden puts several URLs in one cell, one per line.
            Format::BitwardenCsv | Format::OnePasswordCsv => row_url
                .split(['\n', ','])
                .map(str::trim)
                .filter(|url| !url.is_empty())
                .map(str::to_owned)
                .collect(),
            _ if row_url.trim().is_empty() => Vec::new(),
            _ => vec![row_url.trim().to_owned()],
        };
        let totp = totp_address(&row_otp, &row_title, &row_username);
        imported.logins.push(ImportedLogin {
            title: row_title,
            username: row_username,
            password: row_password,
            urls,
            notes: row_notes,
            totp,
        });
    }
    Ok(imported)
}

/// The host of a URL, for a login without a title.
fn host_of(url: &str) -> Option<String> {
    let rest = url
        .trim()
        .split_once("://")
        .map_or(url.trim(), |(_, rest)| rest);
    let host = rest.split(['/', '?', '#']).next()?.rsplit('@').next()?;
    let host = host.split(':').next()?.trim_start_matches("www.");
    (!host.is_empty()).then(|| host.to_owned())
}

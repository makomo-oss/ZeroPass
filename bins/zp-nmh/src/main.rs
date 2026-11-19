//! ZeroPass native messaging host: the browser extension's bridge to the vault
//! daemon (`docs/spec/extension.md` §3).
//!
//! The browser starts this program for the extension and talks to it over
//! standard input and output. It passes each request on to the vault daemon,
//! with the role of the extension bridge: the logins that match a page, and
//! the password of one of them. It holds no secret between requests and has
//! no network connection.

mod frame;
mod message;

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use zeroize::Zeroizing;
use zp_client::KeyStoreChoice;
use zp_client::vaultd::{self, Start};
use zp_ipc::proto::{self, request, response};
use zp_ipc::{Client, IpcError};

use message::{Answer, Failure, Request};

/// The extension's identifiers (`docs/spec/extension.md` §2).
const CHROME_EXTENSIONS: [&str; 1] = ["gehobienihkbhglhnibeobdkgeinamdn"];
const FIREFOX_EXTENSIONS: [&str; 1] = ["zeropass@makomo-oss.github.io"];

/// The most matching logins one answer lists: an answer to the browser may
/// not exceed 1 MiB.
const MAX_LOGINS: usize = 200;

fn log(message: &str) {
    let _ = writeln!(io::stderr(), "zp-nmh: {message}");
}

/// Whether the browser started this program for ZeroPass's extension. Chrome
/// and Edge name the extension's origin first; Firefox names its manifest,
/// then the extension's identifier.
fn started_for_our_extension(args: &[String]) -> bool {
    let chrome = args.first().is_some_and(|origin| {
        CHROME_EXTENSIONS
            .iter()
            .any(|id| origin == &format!("chrome-extension://{id}/"))
    });
    let firefox = args
        .get(1)
        .is_some_and(|id| FIREFOX_EXTENSIONS.contains(&id.as_str()));
    chrome || firefox
}

/// The conversation with the vault daemon, made when first needed.
struct Daemon {
    vault: PathBuf,
    client: Option<Client>,
}

impl Daemon {
    /// Makes one request. The daemon is not started: the browser may end what
    /// this program starts when it lets go of it (§3.3).
    fn call(&mut self, body: request::Body) -> Result<response::Body, Failure> {
        for attempt in 0..2 {
            if self.client.is_none() {
                self.client = vaultd::connect(&self.vault, KeyStoreChoice::Platform, Start::Never)
                    .map_err(|error| Failure::from_client(&error))?;
            }
            let Some(client) = self.client.as_mut() else {
                return Err(Failure::not_running());
            };
            match client.call(body.clone()) {
                Ok(reply) => return Ok(reply),
                // The daemon stopped or restarted: every request of the
                // bridge may be made again.
                Err(IpcError::Io(_) | IpcError::Protocol(_)) if attempt == 0 => {
                    self.client = None;
                }
                Err(error) => {
                    self.client = None;
                    return Err(Failure::from_client(&error.into()));
                }
            }
        }
        Err(Failure::not_running())
    }
}

fn unexpected() -> Failure {
    Failure::new("Internal", "the vault daemon gave an unexpected answer")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn b64url_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((bytes.len() * 4).div_ceil(3));
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = if chunk.len() > 1 {
            u32::from(chunk[1])
        } else {
            0
        };
        let b2 = if chunk.len() > 2 {
            u32::from(chunk[2])
        } else {
            0
        };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((triple >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((triple >> 6) & 0x3F) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(TABLE[(triple & 0x3F) as usize] as char);
        }
    }
    out
}

fn b64url_decode(text: &str) -> Result<Vec<u8>, Failure> {
    let invalid = || Failure::new("BadRequest", "malformed base64url field");
    let bytes = text.as_bytes();
    if bytes.len() % 4 == 1 {
        return Err(invalid());
    }
    let val = |b: u8| -> Result<u32, Failure> {
        match b {
            b'A'..=b'Z' => Ok(u32::from(b - b'A')),
            b'a'..=b'z' => Ok(u32::from(b - b'a' + 26)),
            b'0'..=b'9' => Ok(u32::from(b - b'0' + 52)),
            b'-' => Ok(62),
            b'_' => Ok(63),
            _ => Err(invalid()),
        }
    };
    let mut out = Vec::with_capacity((bytes.len() * 3) / 4);
    for chunk in bytes.chunks(4) {
        let v0 = val(chunk[0])?;
        let v1 = val(chunk[1])?;
        match chunk.len() {
            2 => {
                if (v1 & 0x0F) != 0 {
                    return Err(invalid());
                }
                out.push(((v0 << 2) | (v1 >> 4)) as u8);
            }
            3 => {
                let v2 = val(chunk[2])?;
                if (v2 & 0x03) != 0 {
                    return Err(invalid());
                }
                out.push(((v0 << 2) | (v1 >> 4)) as u8);
                out.push((((v1 & 0x0F) << 4) | (v2 >> 2)) as u8);
            }
            4 => {
                let v2 = val(chunk[2])?;
                let v3 = val(chunk[3])?;
                out.push(((v0 << 2) | (v1 >> 4)) as u8);
                out.push((((v1 & 0x0F) << 4) | (v2 >> 2)) as u8);
                out.push((((v2 & 0x03) << 6) | v3) as u8);
            }
            _ => return Err(invalid()),
        }
    }
    Ok(out)
}

fn b64url_list(items: &[String]) -> Result<Vec<Vec<u8>>, Failure> {
    items.iter().map(|s| b64url_decode(s)).collect()
}

fn passkey_candidates(list: proto::PasskeyCandidates) -> Answer {
    Answer::PasskeyCandidates {
        candidates: list
            .candidates
            .into_iter()
            .take(MAX_LOGINS)
            .map(|c| message::PasskeyCandidate {
                id: hex(&c.item_id),
                credential_id: b64url_encode(&c.credential_id),
                rp_id: c.rp_id,
                rp_name: c.rp_name,
                user_handle: b64url_encode(&c.user_handle),
                user_name: c.user_name,
                user_display_name: c.user_display_name,
                cose_algorithm: c.cose_algorithm,
            })
            .collect(),
    }
}

fn parse_id(text: &str) -> Result<Vec<u8>, Failure> {
    let invalid = || Failure::new("BadRequest", "an item identifier is 32 hexadecimal digits");
    if text.len() != 32 || !text.is_ascii() {
        return Err(invalid());
    }
    (0..16)
        .map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).map_err(|_| invalid()))
        .collect()
}

/// Answers one request of the extension.
fn answer(daemon: &mut Daemon, request: Request) -> Result<Answer, Failure> {
    match request {
        Request::Status => {
            if !daemon.vault.exists() {
                return Ok(Answer::Status {
                    vault: false,
                    running: false,
                    unlocked: false,
                    totp: false,
                    passkey: false,
                });
            }
            let status = match daemon.call(request::Body::Status(proto::Status {})) {
                Ok(response::Body::Status(status)) => status,
                Ok(_) => return Err(unexpected()),
                Err(failure) if failure.is_not_running() => {
                    return Ok(Answer::Status {
                        vault: true,
                        running: false,
                        unlocked: false,
                        totp: false,
                        passkey: false,
                    });
                }
                Err(failure) => return Err(failure),
            };
            let state = |domain: proto::Domain| {
                status
                    .domains
                    .iter()
                    .find(|entry| entry.domain == domain as i32)
                    .copied()
                    .unwrap_or_default()
            };
            Ok(Answer::Status {
                vault: status.vault_exists,
                running: true,
                unlocked: state(proto::Domain::Password).unlocked,
                totp: state(proto::Domain::Totp).available,
                passkey: state(proto::Domain::Passkey).available,
            })
        }
        Request::Find { origin, top } => {
            let find = proto::BridgeFind {
                origin,
                top_origin: top,
            };
            match daemon.call(request::Body::BridgeFind(find))? {
                response::Body::BridgeLogins(found) => Ok(Answer::Logins {
                    logins: found
                        .logins
                        .into_iter()
                        .take(MAX_LOGINS)
                        .map(|login| message::Login {
                            id: hex(&login.item_id),
                            title: login.title,
                            username: login.username,
                            r#match: if login.exact { "exact" } else { "site" },
                        })
                        .collect(),
                }),
                _ => Err(unexpected()),
            }
        }
        Request::Fill { origin, top, item } => {
            let item_id = parse_id(&item)?;
            match daemon.call(request::Body::BridgeFill(proto::BridgeFill {
                origin,
                item_id,
                top_origin: top,
            }))? {
                response::Body::BridgeCredential(credential) => Ok(Answer::Credential {
                    username: Zeroizing::new(credential.username.clone()),
                    password: Zeroizing::new(credential.password.clone()),
                }),
                _ => Err(unexpected()),
            }
        }
        Request::Totp { origin, top, item } => {
            let item_id = parse_id(&item)?;
            // Windows Hello asks the user for every code: the key agent shows
            // the prompt for the daemon, which cannot from its sandbox.
            let _agent = zp_client::KeyAgent::start(&daemon.vault, KeyStoreChoice::Platform)
                .map_err(|error| Failure::from_client(&error))?;
            let totp = proto::BridgeTotp {
                origin,
                top_origin: top,
                item_id,
            };
            match daemon.call(request::Body::BridgeTotp(totp))? {
                response::Body::TotpCode(reply) => Ok(Answer::Code {
                    code: Zeroizing::new(reply.code.clone()),
                }),
                _ => Err(unexpected()),
            }
        }
        Request::Compare {
            origin,
            top,
            username,
            password,
        } => {
            let compare = proto::BridgeCompare {
                origin,
                top_origin: top,
                username,
                password: password.as_str().to_owned(),
            };
            match daemon.call(request::Body::BridgeCompare(compare))? {
                response::Body::BridgeComparison(comparison) => Ok(Answer::Comparison {
                    item: hex(&comparison.item_id),
                    same: comparison.same,
                }),
                _ => Err(unexpected()),
            }
        }
        Request::Save {
            origin,
            top,
            title,
            username,
            password,
        } => {
            let save = proto::BridgeSave {
                origin,
                top_origin: top,
                title,
                username,
                password: password.as_str().to_owned(),
            };
            match daemon.call(request::Body::BridgeSave(save))? {
                response::Body::ItemAdded(added) => Ok(Answer::Saved {
                    item: hex(&added.item_id),
                }),
                _ => Err(unexpected()),
            }
        }
        Request::Update {
            origin,
            top,
            item,
            password,
        } => {
            let update = proto::BridgeUpdate {
                origin,
                top_origin: top,
                item_id: parse_id(&item)?,
                password: password.as_str().to_owned(),
            };
            match daemon.call(request::Body::BridgeUpdate(update))? {
                response::Body::Done(_) => Ok(Answer::Done {}),
                _ => Err(unexpected()),
            }
        }
        Request::PasskeyCreate {
            origin,
            top,
            rp_id,
            rp_name,
            user_handle,
            user_name,
            user_display_name,
            algorithms,
            exclude_credential_ids,
            client_data_hash,
        } => {
            let user_handle = b64url_decode(&user_handle)?;
            let exclude_credential_ids = b64url_list(&exclude_credential_ids)?;
            let client_data_hash = b64url_decode(&client_data_hash)?;
            // Windows Hello verifies the user for every passkey creation.
            let _agent = zp_client::KeyAgent::start(&daemon.vault, KeyStoreChoice::Platform)
                .map_err(|error| Failure::from_client(&error))?;
            let create = proto::PasskeyCreate {
                origin,
                top_origin: top,
                rp_id,
                rp_name,
                user_handle,
                user_name,
                user_display_name,
                algorithms,
                exclude_credential_ids,
                client_data_hash,
            };
            match daemon.call(request::Body::PasskeyCreate(create))? {
                response::Body::PasskeyCreated(created) => Ok(Answer::PasskeyCreated {
                    item: hex(&created.item_id),
                    credential_id: b64url_encode(&created.credential_id),
                    public_key_spki: b64url_encode(&created.public_key_spki),
                    public_key_cose: b64url_encode(&created.public_key_cose),
                    cose_algorithm: created.cose_algorithm,
                    authenticator_data: b64url_encode(&created.authenticator_data),
                    attestation_object: b64url_encode(&created.attestation_object),
                }),
                _ => Err(unexpected()),
            }
        }
        Request::PasskeyList {
            origin,
            top,
            rp_id,
            allow_credential_ids,
        } => {
            let allow_credential_ids = b64url_list(&allow_credential_ids)?;
            let list = proto::PasskeyList {
                origin,
                top_origin: top,
                rp_id,
                allow_credential_ids,
            };
            match daemon.call(request::Body::PasskeyList(list))? {
                response::Body::PasskeyCandidates(candidates) => Ok(passkey_candidates(candidates)),
                _ => Err(unexpected()),
            }
        }
        Request::PasskeyGet {
            origin,
            top,
            rp_id,
            client_data_hash,
            allow_credential_ids,
            credential_id,
        } => {
            let client_data_hash = b64url_decode(&client_data_hash)?;
            let allow_credential_ids = b64url_list(&allow_credential_ids)?;
            let credential_id = if credential_id.is_empty() {
                Vec::new()
            } else {
                b64url_decode(&credential_id)?
            };
            // Windows Hello verifies the user for every passkey assertion.
            let _agent = zp_client::KeyAgent::start(&daemon.vault, KeyStoreChoice::Platform)
                .map_err(|error| Failure::from_client(&error))?;
            let get = proto::PasskeyGetAssertion {
                origin,
                top_origin: top,
                rp_id,
                client_data_hash,
                allow_credential_ids,
                credential_id,
            };
            match daemon.call(request::Body::PasskeyGetAssertion(get))? {
                response::Body::PasskeyAssertion(assertion) => Ok(Answer::PasskeyAssertion {
                    item: hex(&assertion.item_id),
                    credential_id: b64url_encode(&assertion.credential_id),
                    user_handle: b64url_encode(&assertion.user_handle),
                    authenticator_data: b64url_encode(&assertion.authenticator_data),
                    signature: b64url_encode(&assertion.signature),
                }),
                response::Body::PasskeyCandidates(candidates) => Ok(passkey_candidates(candidates)),
                _ => Err(unexpected()),
            }
        }
        Request::OpenApp => {
            open_app().map_err(|error| Failure::new("Internal", &error.to_string()))?;
            Ok(Answer::Done {})
        }
    }
}

/// Starts the desktop application, so that the user can unlock the vault (or
/// start ZeroPass). Out of the browser's job if the browser allows it: the
/// application must outlive this program.
fn open_app() -> io::Result<()> {
    let name = format!("zeropass{}", std::env::consts::EXE_SUFFIX);
    let app = std::env::current_exe()?.with_file_name(name);
    spawn_app(&app)
}

#[cfg(windows)]
fn spawn_app(app: &Path) -> io::Result<()> {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
    let start = |flags: u32| {
        Command::new(app)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(flags)
            .spawn()
            .map(drop)
    };
    // A job that does not allow breaking away refuses the first.
    start(DETACHED_PROCESS | CREATE_BREAKAWAY_FROM_JOB).or_else(|_| start(DETACHED_PROCESS))
}

#[cfg(not(windows))]
fn spawn_app(app: &Path) -> io::Result<()> {
    zp_ipc::spawn_detached(&mut std::process::Command::new(app))
}

fn run() -> io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // What this program starts must not open console windows: the browser
    // runs it without one.
    zp_client::set_windowed();
    if !started_for_our_extension(&args) {
        log("not started for the ZeroPass extension; ending");
        return Ok(());
    }
    let vault = zp_client::vault_path_from_environment()
        .map_err(|error| io::Error::other(error.to_string()))?;
    let mut daemon = Daemon {
        vault,
        client: None,
    };
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    while let Some(bytes) = frame::read(&mut input)? {
        let reply = match serde_json::from_slice::<message::Envelope>(&bytes) {
            Ok(envelope) => message::Reply::new(envelope.id, answer(&mut daemon, envelope.request)),
            Err(error) => message::Reply::new(
                message::id_of(&bytes),
                Err(Failure::new(
                    "BadRequest",
                    &format!("not a request: {error}"),
                )),
            ),
        };
        drop(bytes);
        let encoded = Zeroizing::new(serde_json::to_vec(&reply).map_err(io::Error::other)?);
        frame::write(&mut output, &encoded)?;
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            log(&format!("error: {error}"));
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| (*arg).to_owned()).collect()
    }

    #[test]
    fn only_the_zeropass_extension_is_served() {
        let chrome = format!("chrome-extension://{}/", CHROME_EXTENSIONS[0]);
        assert!(started_for_our_extension(&strings(&[&chrome])));
        assert!(started_for_our_extension(&strings(&[
            &chrome,
            "--parent-window=0"
        ])));
        assert!(started_for_our_extension(&strings(&[
            r"C:\Program Files\ZeroPass\zp-nmh-firefox.json",
            FIREFOX_EXTENSIONS[0]
        ])));
        for others in [
            &[][..],
            &["chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"][..],
            &["chrome-extension://gehobienihkbhglhnibeobdkgeinamdn"][..],
            &["manifest.json", "evil@example.com"][..],
        ] {
            assert!(!started_for_our_extension(&strings(others)), "{others:?}");
        }
    }

    #[test]
    fn item_ids_are_read_strictly() {
        assert_eq!(parse_id(&"ab".repeat(16)).unwrap(), vec![0xab; 16]);
        assert!(parse_id("").is_err());
        assert!(parse_id(&"g".repeat(32)).is_err());
        assert!(parse_id(&"é".repeat(16)).is_err());
    }

    #[test]
    fn base64url_round_trips_and_rejects_malformed() {
        for bytes in [
            &[][..],
            &[0][..],
            &[0xfb, 0xff][..],
            &[0xfb, 0xff, 0xfe][..],
            b"hello passkey world",
        ] {
            let encoded = b64url_encode(bytes);
            assert_eq!(b64url_decode(&encoded).unwrap(), bytes);
        }
        for bad in ["a", "abc=", "ab+c", "ab/c", "Zh"] {
            assert!(b64url_decode(bad).is_err(), "{bad:?}");
        }
    }
}

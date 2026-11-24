//! ZeroPass native messaging host: the browser extension's bridge to the vault
//! daemon (`docs/spec/extension.md` §3).
//!
//! The browser starts this program for the extension and talks to it over
//! standard input and output. It passes each request on to the vault daemon,
//! with the role of the extension bridge: the logins that match a page, and
//! the password of one of them. It holds no secret between requests and has
//! no network connection.

mod base64url;
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

/// Bytes the extension sent as base64url.
fn bytes(text: &str) -> Result<Vec<u8>, Failure> {
    base64url::decode(text).ok_or_else(|| {
        Failure::new(
            "BadRequest",
            "bytes are written in base64url without padding",
        )
    })
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
                    passkeys: false,
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
                        passkeys: false,
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
                passkeys: state(proto::Domain::Passkey).available,
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
            user_id,
            user_name,
            user_display_name,
            challenge,
            algorithms,
            exclude,
        } => {
            let create = proto::PasskeyCreate {
                origin,
                top_origin: top,
                rp_id,
                rp_name,
                user_handle: bytes(&user_id)?,
                user_name,
                user_display_name,
                challenge: bytes(&challenge)?,
                algorithms,
                exclude: exclude
                    .iter()
                    .map(|id| bytes(id))
                    .collect::<Result<_, _>>()?,
                client_data_hash: Vec::new(),
            };
            // Windows Hello asks the user for every passkey (§9).
            let _agent = zp_client::KeyAgent::start(&daemon.vault, KeyStoreChoice::Platform)
                .map_err(|error| Failure::from_client(&error))?;
            match daemon.call(request::Body::PasskeyCreate(create))? {
                response::Body::PasskeyCreated(created) => Ok(Answer::PasskeyCreated {
                    credential_id: base64url::encode(&created.credential_id),
                    client_data_json: base64url::encode(&created.client_data_json),
                    attestation_object: base64url::encode(&created.attestation_object),
                    authenticator_data: base64url::encode(&created.authenticator_data),
                    public_key: base64url::encode(&created.public_key),
                    algorithm: created.algorithm,
                }),
                _ => Err(unexpected()),
            }
        }
        Request::PasskeyGet {
            origin,
            top,
            rp_id,
            challenge,
            allow,
            chosen,
        } => {
            let get = proto::PasskeyGet {
                origin,
                top_origin: top,
                rp_id,
                challenge: bytes(&challenge)?,
                allow: allow.iter().map(|id| bytes(id)).collect::<Result<_, _>>()?,
                chosen: bytes(&chosen)?,
                client_data_hash: Vec::new(),
                list_only: false,
            };
            let _agent = zp_client::KeyAgent::start(&daemon.vault, KeyStoreChoice::Platform)
                .map_err(|error| Failure::from_client(&error))?;
            match daemon.call(request::Body::PasskeyGet(get))? {
                response::Body::PasskeyAssertion(assertion) => Ok(Answer::PasskeyAssertion {
                    credential_id: base64url::encode(&assertion.credential_id),
                    client_data_json: base64url::encode(&assertion.client_data_json),
                    authenticator_data: base64url::encode(&assertion.authenticator_data),
                    signature: base64url::encode(&assertion.signature),
                    user_handle: base64url::encode(&assertion.user_handle),
                }),
                response::Body::PasskeyChoices(choices) => Ok(Answer::PasskeyChoices {
                    choices: choices
                        .choices
                        .into_iter()
                        .map(|choice| message::PasskeyChoice {
                            credential_id: base64url::encode(&choice.credential_id),
                            user_name: choice.user_name,
                            display_name: choice.user_display_name,
                        })
                        .collect(),
                }),
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

/// Inheriting none of this program's handles: its standard input and output
/// are the browser's pipes, which the application must not keep open.
#[cfg(windows)]
fn spawn_app(app: &Path) -> io::Result<()> {
    zp_ipc::spawn_detached_out_of_job(&mut std::process::Command::new(app))
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
}

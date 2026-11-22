//! The vault's items, as the page sees them (P4-02).
//!
//! The page gets the summaries and the details of an item, but a login's
//! password only when the user asks to see it. Copying goes from the daemon's
//! answer to the clipboard without passing through the page.

use serde::{Deserialize, Serialize};
use tauri::AppHandle;
use zeroize::Zeroizing;
use zp_client::vaultd::Start;
use zp_ipc::proto::{self, ErrorCode, item, new_item, request, response};

use crate::AppState;
use crate::commands::{blocking, hex, parse_domain};
use crate::error::{CommandError, CommandResult};
use crate::{clipboard, generator};

fn unexpected() -> CommandError {
    CommandError::client("the vault daemon gave an unexpected answer")
}

/// An item identifier from the page: 32 hexadecimal digits.
fn parse_id(text: &str) -> CommandResult<Vec<u8>> {
    let invalid = || CommandError::client("an item identifier is 32 hexadecimal digits");
    if text.len() != 32 || !text.is_ascii() {
        return Err(invalid());
    }
    (0..16)
        .map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).map_err(|_| invalid()))
        .collect()
}

fn kind_name(kind: i32) -> &'static str {
    match proto::ItemKind::try_from(kind) {
        Ok(proto::ItemKind::Login) => "login",
        Ok(proto::ItemKind::Note) => "note",
        Ok(proto::ItemKind::Totp) => "totp",
        Ok(proto::ItemKind::Passkey) => "passkey",
        _ => "unknown",
    }
}

impl AppState {
    /// Makes a request that may meet a locked hardware-bound domain: that
    /// domain is unlocked with Windows Hello (through the key agent), and the
    /// request made again — for each such domain the request needs. A locked
    /// password domain is the page's to handle.
    pub(crate) fn call_unlocking(&self, request: request::Body) -> CommandResult<response::Body> {
        // The TOTP and the passkey domain may each need unlocking once.
        for _ in 0..2 {
            match self.daemon.call(request.clone()) {
                Err(error) if error.code() == Some(ErrorCode::Locked) => {
                    let domain = error
                        .remote()
                        .and_then(|remote| remote.domain)
                        .and_then(|domain| proto::Domain::try_from(domain).ok());
                    match domain {
                        Some(domain @ (proto::Domain::Totp | proto::Domain::Passkey)) => {
                            self.daemon.call_with_key_agent(
                                Start::IfVaultExists,
                                request::Body::Unlock(proto::Unlock {
                                    domain: domain as i32,
                                    master_password: String::new(),
                                }),
                            )?;
                        }
                        _ => return Err(error.into()),
                    }
                }
                other => return Ok(other?),
            }
        }
        Ok(self.daemon.call(request)?)
    }

    /// The state of the vault, from the daemon.
    pub(crate) fn status(&self) -> CommandResult<proto::StatusReply> {
        match self.daemon.call(request::Body::Status(proto::Status {}))? {
            response::Body::Status(status) => Ok(status),
            _ => Err(unexpected()),
        }
    }

    /// Unlocks a hardware-bound domain: Windows Hello asks, through the key
    /// agent.
    pub(crate) fn unlock_hardware(&self, domain: proto::Domain) -> CommandResult<()> {
        self.daemon.call_with_key_agent(
            Start::IfVaultExists,
            request::Body::Unlock(proto::Unlock {
                domain: domain as i32,
                master_password: String::new(),
            }),
        )?;
        Ok(())
    }

    fn get(&self, id: Vec<u8>) -> CommandResult<proto::Item> {
        match self.call_unlocking(request::Body::GetItem(proto::GetItem { item_id: id }))? {
            response::Body::Item(item) => Ok(item),
            _ => Err(unexpected()),
        }
    }
}

/// What a list shows of an item.
#[derive(Serialize)]
pub(crate) struct Summary {
    id: String,
    kind: &'static str,
    title: String,
    username: String,
    urls: Vec<String>,
}

/// The items of a domain, and how many this device cannot open yet.
#[derive(Serialize)]
pub(crate) struct Listing {
    items: Vec<Summary>,
    /// Live items written with keys that have not reached this device
    /// (ADR-0011): they are not in `items`.
    unreadable: u32,
}

/// The items of a domain. A locked domain is an error (`Locked`): listing
/// does not prompt for Windows Hello by itself.
#[tauri::command]
pub(crate) async fn list_items(app: AppHandle, domain: String) -> CommandResult<Listing> {
    let domain = parse_domain(&domain)?;
    blocking(app, move |state| {
        let list = request::Body::ListItems(proto::ListItems {
            domain: domain as i32,
            query: String::new(),
        });
        let response::Body::Items(items) = state.daemon.call(list)? else {
            return Err(unexpected());
        };
        Ok(Listing {
            items: items
                .items
                .into_iter()
                .map(|summary| Summary {
                    id: hex(&summary.item_id),
                    kind: kind_name(summary.kind),
                    title: summary.title,
                    username: summary.username,
                    urls: summary.urls,
                })
                .collect(),
            unreadable: items.unreadable,
        })
    })
    .await
}

/// The details of an item. A login's password is not among them
/// ([`reveal_password`]).
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub(crate) enum Details {
    Login {
        id: String,
        title: String,
        username: String,
        urls: Vec<String>,
        notes: String,
        has_password: bool,
    },
    Note {
        id: String,
        title: String,
        body: String,
    },
    Totp {
        id: String,
        issuer: String,
        account: String,
        digits: u32,
        period: u32,
        login_id: Option<String>,
    },
    Passkey {
        id: String,
        rp_id: String,
        user_name: String,
    },
}

#[tauri::command]
pub(crate) async fn get_item(app: AppHandle, id: String) -> CommandResult<Details> {
    let item_id = parse_id(&id)?;
    blocking(app, move |state| {
        let item = state.get(item_id)?;
        Ok(match item.content {
            Some(item::Content::Login(login)) => Details::Login {
                id,
                title: login.title.clone(),
                username: login.username.clone(),
                urls: login.urls.clone(),
                notes: login.notes.clone(),
                has_password: !login.password.is_empty(),
            },
            Some(item::Content::Note(note)) => Details::Note {
                id,
                title: note.title.clone(),
                body: note.body.clone(),
            },
            Some(item::Content::Totp(totp)) => Details::Totp {
                id,
                issuer: totp.issuer,
                account: totp.account,
                digits: totp.digits,
                period: totp.period,
                login_id: totp.login_id.as_deref().map(hex),
            },
            Some(item::Content::Passkey(passkey)) => Details::Passkey {
                id,
                rp_id: passkey.rp_id,
                user_name: passkey.user_name,
            },
            None => return Err(unexpected()),
        })
    })
    .await
}

/// The password of a login, for the user who asked to see it.
#[tauri::command]
pub(crate) async fn reveal_password(app: AppHandle, id: String) -> CommandResult<String> {
    let item_id = parse_id(&id)?;
    blocking(app, move |state| match state.get(item_id)?.content {
        Some(item::Content::Login(login)) => Ok(login.password.clone()),
        _ => Err(CommandError::client("only a login has a password")),
    })
    .await
}

/// What [`copy`] copies.
#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Field {
    Password,
    Username,
    /// The text of a secure note.
    Note,
    /// The current code of a TOTP entry.
    Code,
}

/// Copies a field of an item to the clipboard, which is cleared after 30
/// seconds. The value does not pass through the page.
#[tauri::command]
pub(crate) async fn copy(app: AppHandle, id: String, field: Field) -> CommandResult<()> {
    let item_id = parse_id(&id)?;
    blocking(app, move |state| {
        let secret = Zeroizing::new(match field {
            Field::Code => {
                let code = proto::TotpCode { item_id };
                match state.call_unlocking(request::Body::TotpCode(code))? {
                    response::Body::TotpCode(reply) => reply.code.clone(),
                    _ => return Err(unexpected()),
                }
            }
            Field::Password | Field::Username | Field::Note => {
                match (field, state.get(item_id)?.content) {
                    (Field::Password, Some(item::Content::Login(login))) => login.password.clone(),
                    (Field::Username, Some(item::Content::Login(login))) => login.username.clone(),
                    (Field::Note, Some(item::Content::Note(note))) => note.body.clone(),
                    _ => return Err(CommandError::client("the item has no such field")),
                }
            }
        });
        clipboard::copy(&secret).map_err(|error| CommandError::client(error.to_string()))
    })
    .await
}

/// A login as the page edits it. `password` is `None` when the user did not
/// change it (the page never had it).
#[derive(Deserialize)]
pub(crate) struct LoginInput {
    title: String,
    username: String,
    password: Option<String>,
    urls: Vec<String>,
    notes: String,
}

/// A secure note as the page edits it.
#[derive(Deserialize)]
pub(crate) struct NoteInput {
    title: String,
    body: String,
}

fn clean_urls(urls: Vec<String>) -> Vec<String> {
    urls.into_iter()
        .map(|url| url.trim().to_owned())
        .filter(|url| !url.is_empty())
        .collect()
}

fn added(reply: response::Body) -> CommandResult<String> {
    match reply {
        response::Body::ItemAdded(added) => Ok(hex(&added.item_id)),
        _ => Err(unexpected()),
    }
}

fn add_request(content: new_item::Content) -> request::Body {
    request::Body::AddItem(proto::AddItem {
        item: Some(proto::NewItem {
            content: Some(content),
        }),
    })
}

#[tauri::command]
pub(crate) async fn add_login(app: AppHandle, login: LoginInput) -> CommandResult<String> {
    blocking(app, move |state| {
        let password = Zeroizing::new(login.password.unwrap_or_default());
        let content = new_item::Content::Login(proto::Login {
            title: login.title,
            username: login.username,
            password: password.as_str().to_owned(),
            urls: clean_urls(login.urls),
            notes: login.notes,
        });
        added(state.daemon.call(add_request(content))?)
    })
    .await
}

#[tauri::command]
pub(crate) async fn update_login(
    app: AppHandle,
    id: String,
    login: LoginInput,
) -> CommandResult<()> {
    let item_id = parse_id(&id)?;
    blocking(app, move |state| {
        // The page sends the password only if the user changed it.
        let password = match login.password {
            Some(password) => Zeroizing::new(password),
            None => match state.get(item_id.clone())?.content {
                Some(item::Content::Login(current)) => Zeroizing::new(current.password.clone()),
                _ => return Err(CommandError::client("the item is not a login")),
            },
        };
        let content = new_item::Content::Login(proto::Login {
            title: login.title,
            username: login.username,
            password: password.as_str().to_owned(),
            urls: clean_urls(login.urls),
            notes: login.notes,
        });
        state
            .daemon
            .call(request::Body::UpdateItem(proto::UpdateItem {
                item_id,
                item: Some(proto::NewItem {
                    content: Some(content),
                }),
            }))?;
        Ok(())
    })
    .await
}

#[tauri::command]
pub(crate) async fn add_note(app: AppHandle, note: NoteInput) -> CommandResult<String> {
    blocking(app, move |state| {
        let content = new_item::Content::Note(proto::Note {
            title: note.title,
            body: note.body,
        });
        added(state.daemon.call(add_request(content))?)
    })
    .await
}

#[tauri::command]
pub(crate) async fn update_note(app: AppHandle, id: String, note: NoteInput) -> CommandResult<()> {
    let item_id = parse_id(&id)?;
    blocking(app, move |state| {
        let content = new_item::Content::Note(proto::Note {
            title: note.title,
            body: note.body,
        });
        state
            .daemon
            .call(request::Body::UpdateItem(proto::UpdateItem {
                item_id,
                item: Some(proto::NewItem {
                    content: Some(content),
                }),
            }))?;
        Ok(())
    })
    .await
}

/// Adds a TOTP entry from its `otpauth://` URI, optionally tied to a login.
/// The seed goes to the daemon and never comes back.
#[tauri::command]
pub(crate) async fn add_totp(
    app: AppHandle,
    uri: String,
    login_id: Option<String>,
) -> CommandResult<String> {
    let uri = Zeroizing::new(uri);
    let login_id = login_id.as_deref().map(parse_id).transpose()?;
    blocking(app, move |state| {
        let content = new_item::Content::Totp(proto::NewTotp {
            otpauth_uri: uri.trim().to_owned(),
            login_id,
        });
        added(state.call_unlocking(add_request(content))?)
    })
    .await
}

#[tauri::command]
pub(crate) async fn delete_item(app: AppHandle, id: String) -> CommandResult<()> {
    let item_id = parse_id(&id)?;
    blocking(app, move |state| {
        state.call_unlocking(request::Body::DeleteItem(proto::DeleteItem { item_id }))?;
        Ok(())
    })
    .await
}

/// The current code of a TOTP entry. The TOTP domain must be unlocked: the
/// page shows codes only after Windows Hello (`unlock`).
#[derive(Serialize)]
pub(crate) struct Code {
    code: String,
    seconds_remaining: u32,
}

#[tauri::command]
pub(crate) async fn totp_code(app: AppHandle, id: String) -> CommandResult<Code> {
    let item_id = parse_id(&id)?;
    blocking(app, move |state| {
        match state
            .daemon
            .call(request::Body::TotpCode(proto::TotpCode { item_id }))?
        {
            response::Body::TotpCode(reply) => Ok(Code {
                code: reply.code.clone(),
                seconds_remaining: reply.seconds_remaining,
            }),
            _ => Err(unexpected()),
        }
    })
    .await
}

#[tauri::command]
pub(crate) fn generate_password(
    options: generator::Options,
) -> CommandResult<generator::Generated> {
    generator::generate(options).map_err(|error| CommandError::client(error.to_string()))
}

/// Creates the recovery kit and returns the recovery key, once. Every domain
/// must be unlocked: the hardware-bound ones are unlocked here with Windows
/// Hello if necessary.
#[tauri::command]
pub(crate) async fn create_recovery_kit(app: AppHandle, replace: bool) -> CommandResult<String> {
    blocking(app, move |state| {
        let kit = request::Body::CreateRecoveryKit(proto::CreateRecoveryKit { replace });
        match state.call_unlocking(kit)? {
            response::Body::RecoveryKit(kit) => Ok(kit.recovery_key.clone()),
            _ => Err(unexpected()),
        }
    })
    .await
}

/// Changes the master password. The password domain locks: it is unlocked
/// again with the new one.
#[tauri::command]
pub(crate) async fn change_master_password(
    app: AppHandle,
    current: String,
    new: String,
) -> CommandResult<()> {
    let current = Zeroizing::new(current);
    let new = Zeroizing::new(new);
    blocking(app, move |state| {
        state.daemon.call(request::Body::ChangeMasterPassword(
            proto::ChangeMasterPassword {
                current: current.as_str().to_owned(),
                new: new.as_str().to_owned(),
            },
        ))?;
        Ok(())
    })
    .await
}

/// Copies text the page already shows (a generated password) the same way
/// as a secret of the vault: kept out of the clipboard history, cleared after
/// 30 seconds.
#[tauri::command]
pub(crate) async fn copy_text(app: AppHandle, text: String) -> CommandResult<()> {
    let text = Zeroizing::new(text);
    blocking(app, move |_| {
        clipboard::copy(&text).map_err(|error| CommandError::client(error.to_string()))
    })
    .await
}

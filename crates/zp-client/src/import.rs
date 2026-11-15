//! Adding what another password manager exported (`zp_import`) to the vault,
//! one item at a time, through the vault daemon.

use zp_import::Imported;
use zp_ipc::proto::{self, new_item, request, response};

use crate::{Error, Result};

/// What was added, and what could not be.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Added {
    /// Logins added.
    pub logins: usize,
    /// Secure notes added.
    pub notes: usize,
    /// One-time-code entries added, tied to their logins.
    pub totp: usize,
    /// Why some could not be added: one line each, without secrets.
    pub failures: Vec<String>,
}

fn add(content: new_item::Content) -> request::Body {
    request::Body::AddItem(proto::AddItem {
        item: Some(proto::NewItem {
            content: Some(content),
        }),
    })
}

/// Adds every login and note of `imported`, and the one-time-code entries of
/// the logins. `call` makes one request of the daemon; it may unlock what it
/// meets locked (the TOTP domain, through Windows Hello). A failure of one
/// item does not stop the others, except a failure to reach the daemon.
pub fn add_imported(
    imported: &Imported,
    mut call: impl FnMut(request::Body) -> Result<response::Body>,
) -> Result<Added> {
    let mut added = Added::default();
    for login in &imported.logins {
        let content = new_item::Content::Login(proto::Login {
            title: login.title.clone(),
            username: login.username.clone(),
            password: login.password.clone(),
            urls: login.urls.clone(),
            notes: login.notes.clone(),
        });
        let id = match call(add(content)) {
            Ok(response::Body::ItemAdded(item)) => item.item_id,
            Ok(_) => return Err(Error::message("the vault daemon gave an unexpected answer")),
            Err(error @ Error::Ipc(zp_ipc::IpcError::Io(_))) => return Err(error),
            Err(error) => {
                added
                    .failures
                    .push(format!("login \"{}\": {error}", login.title));
                continue;
            }
        };
        added.logins += 1;
        if let Some(uri) = &login.totp {
            let totp = new_item::Content::Totp(proto::NewTotp {
                otpauth_uri: uri.clone(),
                login_id: Some(id),
            });
            match call(add(totp)) {
                Ok(_) => added.totp += 1,
                Err(error) => added
                    .failures
                    .push(format!("one-time code of \"{}\": {error}", login.title)),
            }
        }
    }
    for note in &imported.notes {
        let content = new_item::Content::Note(proto::Note {
            title: note.title.clone(),
            body: note.body.clone(),
        });
        match call(add(content)) {
            Ok(_) => added.notes += 1,
            Err(error) => added
                .failures
                .push(format!("note \"{}\": {error}", note.title)),
        }
    }
    Ok(added)
}

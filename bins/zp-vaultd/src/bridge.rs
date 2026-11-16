//! What the browser extension may ask, through its bridge `zp-nmh`
//! (`docs/spec/extension.md` §4).
//!
//! The daemon decides which logins belong to the page whose origin the
//! extension names (`zp-origin`), and hands out a password only for one login
//! that does, in a frame of the same site as the tab's top frame.

use zp_crypto::Password;
use zp_ipc::proto::{self, ErrorCode, response};
use zp_origin::{Match, Origin};
use zp_vault::Vault;
use zp_vault::model::{Content, Login};

use crate::convert::{self, bad_request, vault_error};
use crate::service::Reply;

/// The page to fill: its origin, if it may be filled at all. A frame of
/// another site than the tab's top frame may not (clickjacking).
fn page(origin: &str, top: &str) -> Result<Option<Origin>, proto::Error> {
    let page = Origin::parse(origin).map_err(|error| bad_request(&error.to_string()))?;
    if !top.is_empty() {
        let top = Origin::parse(top).map_err(|error| bad_request(&error.to_string()))?;
        if !page.same_site(&top) {
            return Ok(None);
        }
    }
    Ok(Some(page))
}

/// The logins that match the page, best first: exact matches, then by title.
pub(crate) fn find(vault: &mut Vault, request: &proto::BridgeFind) -> Reply {
    let Some(page) = page(&request.origin, &request.top_origin)? else {
        return Ok(response::Body::BridgeLogins(proto::BridgeLogins::default()));
    };
    let mut found: Vec<(Match, proto::BridgeLogin)> = vault
        .list::<Password>()
        .map_err(vault_error)?
        .into_iter()
        .filter_map(|(id, content)| match content {
            Content::Login(login) => {
                let level = page.best_match(login.urls.iter().map(String::as_str))?;
                Some((
                    level,
                    proto::BridgeLogin {
                        item_id: id.as_bytes().to_vec(),
                        title: login.title.clone(),
                        username: login.username.clone(),
                        exact: level == Match::Exact,
                    },
                ))
            }
            _ => None,
        })
        .collect();
    found.sort_by(|(a, x), (b, y)| {
        b.cmp(a)
            .then_with(|| x.title.to_lowercase().cmp(&y.title.to_lowercase()))
            .then_with(|| x.username.cmp(&y.username))
    });
    Ok(response::Body::BridgeLogins(proto::BridgeLogins {
        logins: found.into_iter().map(|(_, login)| login).collect(),
    }))
}

/// The user name and password of one login, if it belongs to the page.
pub(crate) fn fill(vault: &mut Vault, request: &proto::BridgeFill) -> Reply {
    let Some(page) = page(&request.origin, &request.top_origin)? else {
        return Err(proto::Error::new(
            ErrorCode::Denied,
            "the page is a frame of another site",
        ));
    };
    let id = convert::item_id(&request.item_id)?;
    let login: Login = vault.get(id).map_err(vault_error)?;
    if page
        .best_match(login.urls.iter().map(String::as_str))
        .is_none()
    {
        return Err(proto::Error::new(
            ErrorCode::Denied,
            "that login does not belong to this page",
        ));
    }
    Ok(response::Body::BridgeCredential(proto::BridgeCredential {
        username: login.username.clone(),
        password: login.password.clone(),
    }))
}

/// A login of the page: it must exist and match the page.
fn page_login(
    vault: &mut Vault,
    page: &Origin,
    item_id: &[u8],
) -> Result<(zp_crypto::ItemId, Login), proto::Error> {
    let id = convert::item_id(item_id)?;
    let login: Login = vault.get(id).map_err(vault_error)?;
    if page
        .best_match(login.urls.iter().map(String::as_str))
        .is_none()
    {
        return Err(proto::Error::new(
            ErrorCode::Denied,
            "that login does not belong to this page",
        ));
    }
    Ok((id, login))
}

fn framed() -> proto::Error {
    proto::Error::new(ErrorCode::Denied, "the page is a frame of another site")
}

/// Checks that a login belongs to the page, for a request answered by another
/// process of the daemon (the TOTP worker).
pub(crate) fn check(
    vault: &mut Vault,
    origin: &str,
    top: &str,
    item_id: &[u8],
) -> Result<(), proto::Error> {
    let page = page(origin, top)?.ok_or_else(framed)?;
    page_login(vault, &page, item_id).map(drop)
}

/// Whether the user name and password typed into the page are already in the
/// vault (`docs/spec/extension.md` §8).
pub(crate) fn compare(vault: &mut Vault, request: &proto::BridgeCompare) -> Reply {
    let page = page(&request.origin, &request.top_origin)?.ok_or_else(framed)?;
    let username = request.username.trim().to_lowercase();
    let mut logins = Vec::new();
    for (id, content) in vault.list::<Password>().map_err(vault_error)? {
        let Content::Login(login) = content else {
            continue;
        };
        if page
            .best_match(login.urls.iter().map(String::as_str))
            .is_some()
        {
            logins.push((id, login));
        }
    }
    let typed = |login: &Login| login.password == request.password;
    let (item_id, same) = if username.is_empty() {
        // The page did not show the user name (a site that remembers who
        // signs in asks for the password only). A login of the page with
        // that password is the one. Otherwise there is no telling which
        // login changed, and only a page without logins gets an offer: to
        // save it.
        let known = logins.iter().any(|(_, login)| typed(login));
        (Vec::new(), known || !logins.is_empty())
    } else {
        // User names are compared regardless of case: "Alice" and "alice"
        // sign in to the same account almost everywhere.
        let named: Vec<_> = logins
            .iter()
            .filter(|(_, login)| login.username.trim().to_lowercase() == username)
            .collect();
        if let Some((id, _)) = named.iter().find(|(_, login)| typed(login)) {
            (id.as_bytes().to_vec(), true)
        } else if let Some((id, _)) = named.first() {
            (id.as_bytes().to_vec(), false)
        } else {
            // A login saved from a page that did not show the user name is
            // the same login when it has that password.
            let unnamed = logins
                .iter()
                .any(|(_, login)| login.username.trim().is_empty() && typed(login));
            (Vec::new(), unnamed)
        }
    };
    Ok(response::Body::BridgeComparison(proto::BridgeComparison {
        item_id,
        same,
    }))
}

/// Saves a new login for the page, with the page's origin as its URL.
pub(crate) fn save(vault: &mut Vault, request: &proto::BridgeSave) -> Reply {
    let page = page(&request.origin, &request.top_origin)?.ok_or_else(framed)?;
    if request.password.is_empty() {
        return Err(bad_request("a login to save needs a password"));
    }
    let title = if request.title.trim().is_empty() {
        page.host().trim_start_matches("www.").to_owned()
    } else {
        request.title.trim().to_owned()
    };
    let login = Login::new(title, request.username.trim(), request.password.as_str())
        .with_url(page.to_string());
    let id = vault.insert(login).map_err(vault_error)?;
    Ok(response::Body::ItemAdded(proto::ItemAdded {
        item_id: id.as_bytes().to_vec(),
    }))
}

/// Replaces the password of a login of the page. The rest stays.
pub(crate) fn update(vault: &mut Vault, request: &proto::BridgeUpdate) -> Reply {
    let page = page(&request.origin, &request.top_origin)?.ok_or_else(framed)?;
    if request.password.is_empty() {
        return Err(bad_request("the new password is empty"));
    }
    let (id, mut login) = page_login(vault, &page, &request.item_id)?;
    login.password = request.password.clone();
    vault.update(id, login).map_err(vault_error)?;
    Ok(response::Body::Done(proto::Done {}))
}

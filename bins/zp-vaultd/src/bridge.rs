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

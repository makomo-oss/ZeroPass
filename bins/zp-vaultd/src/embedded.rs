//! The vault daemon embedded in another process: the vault process of the
//! Android app (ADR-0012, `docs/spec/ipc.md` §14).
//!
//! That process is an `isolatedProcess` service: it has no permission, cannot
//! open the app's files and cannot use the app's Android Keystore keys. The
//! app hands it one end of a socket pair for every connection, and the engine
//! answers the same requests as the daemon, with every domain in this one
//! process. Two relays the app keeps open stand in for what the process cannot
//! do itself:
//!
//! - the **image host** (`ImageHostAttach`) gives the stored vault file and
//!   stores every new image of it, before the request that changed the vault
//!   is answered;
//! - the **key agent** (`KeyAgentAttach`) answers for the hardware key store.

use std::io::{Read, Write};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::thread;
use std::time::{Duration, Instant};

use zp_crypto::DomainId;
use zp_ipc::proto::{self, ErrorCode, Role, request, response};
use zp_ipc::{Handler, Peer, RelayEnd, StreamServer};

use crate::agent::AgentLink;
use crate::convert::{self, bad_request};
use crate::image::ImageHost;
use crate::port::KeyAgentPort;
use crate::service::{KeyStoreChoice, Reply, Scope, Service, Storage};

/// How often idle domains are checked for their timeout.
const TICK: Duration = Duration::from_secs(1);

/// How long the user has to pick one of several passkeys without being asked
/// again (`docs/spec/passkey.md` §9).
const CHOICE_TIME: Duration = Duration::from_secs(120);

/// A request for an assertion that found several passkeys, for which the
/// user was just verified: the same request with one of them picked is
/// signed without asking again. Nothing in it is secret.
struct PendingChoice {
    request: proto::PasskeyGet,
    choices: Vec<Vec<u8>>,
    expires: Instant,
}

impl PendingChoice {
    fn answered_by(&self, request: &proto::PasskeyGet) -> bool {
        let pending = &self.request;
        Instant::now() < self.expires
            && request.origin == pending.origin
            && request.top_origin == pending.top_origin
            && request.rp_id == pending.rp_id
            && request.challenge == pending.challenge
            && request.allow == pending.allow
            && self.choices.contains(&request.chosen)
    }
}

fn as_result(reply: response::Body) -> Reply {
    match reply {
        response::Body::Error(error) => Err(error),
        reply => Ok(reply),
    }
}

struct Inner {
    service: Service,
    agent: Arc<AgentLink>,
    host: ImageHost,
    /// Passkeys the user is picking from, if any.
    choice: Mutex<Option<PendingChoice>>,
}

/// The vault daemon of the vault process of the Android app.
pub struct Engine {
    inner: Arc<Inner>,
    server: StreamServer,
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for Engine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Engine").finish_non_exhaustive()
    }
}

impl Engine {
    /// The engine of this process. It knows no vault until the app attaches
    /// its image host, and has no hardware key store until the app attaches
    /// its key agent. Idle domains lock themselves as in the daemon.
    pub fn new() -> Self {
        let agent = Arc::new(AgentLink::default());
        let port: Arc<dyn KeyAgentPort> = agent.clone();
        let service = Service::new(Storage::Image, KeyStoreChoice::Platform, Scope::Whole, port)
            .unwrap_or_else(|error| {
                // Only fails without randomness from the system, which nothing here can work without.
                panic!("the vault engine cannot start: {}", error.message)
            });
        let inner = Arc::new(Inner {
            service,
            agent,
            host: ImageHost::default(),
            choice: Mutex::new(None),
        });
        let weak: Weak<Inner> = Arc::downgrade(&inner);
        thread::spawn(move || {
            while let Some(inner) = weak.upgrade() {
                inner.service.tick();
                drop(inner);
                thread::sleep(TICK);
            }
        });
        Self {
            inner,
            server: StreamServer::new(Role::Ui, env!("CARGO_PKG_VERSION")),
        }
    }

    /// Runs one conversation on `stream`, which the app connected, until the
    /// app closes it. Blocks: give every connection a thread of its own.
    pub fn converse<S: Read + Write>(&self, mut stream: S) {
        let _ = self.server.converse(&mut stream, self.inner.as_ref());
    }
}

impl Inner {
    fn choice(&self) -> MutexGuard<'_, Option<PendingChoice>> {
        self.choice
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    fn serve(&self, request: request::Body) -> Reply {
        as_result(self.service.serve(request))
    }

    /// Verifies the user anew for one use of a hardware-bound domain: the
    /// domain is locked and unlocked through the key agent (biometrics), even
    /// if it was open, as the daemon does for the browser extension.
    fn verify_user(&self, domain: DomainId) -> Result<(), proto::Error> {
        if !self.service.has_domain(domain)? {
            return Err(proto::Error::about(
                ErrorCode::DomainUnavailable,
                convert::domain_to_proto(domain),
                format!(
                    "this vault has no {} domain on this device",
                    convert::domain_name(domain)
                ),
            ));
        }
        let domain = convert::domain_to_proto(domain) as i32;
        if self.service.unlocked(convert::domain_from_proto(domain)?) {
            self.serve(request::Body::Lock(proto::Lock {
                domain: Some(domain),
            }))?;
        }
        self.serve(request::Body::Unlock(proto::Unlock {
            domain,
            master_password: String::new(),
        }))
        .map(drop)
    }

    /// The one-time code tied to a login of the page, with the user verified
    /// for every code (`docs/spec/extension.md` §9).
    fn bridge_totp(&self, request: &proto::BridgeTotp) -> Reply {
        self.service
            .bridge_check(&request.origin, &request.top_origin, &request.item_id)?;
        self.verify_user(DomainId::Totp)?;
        let list = request::Body::ListItems(proto::ListItems {
            domain: proto::Domain::Totp as i32,
            query: String::new(),
        });
        let response::Body::Items(items) = self.serve(list)? else {
            return Err(bad_request("the list of one-time codes was not a list"));
        };
        for summary in items.items {
            let get = request::Body::GetItem(proto::GetItem {
                item_id: summary.item_id.clone(),
            });
            if let response::Body::Item(proto::Item {
                content: Some(proto::item::Content::Totp(info)),
                ..
            }) = self.serve(get)?
                && info.login_id.as_deref() == Some(request.item_id.as_slice())
            {
                return self.serve(request::Body::TotpCode(proto::TotpCode {
                    item_id: summary.item_id,
                }));
            }
        }
        Err(proto::Error::new(
            ErrorCode::ItemNotFound,
            "no one-time code is tied to that login",
        ))
    }

    fn passkey_create(&self, create: proto::PasskeyCreate) -> Reply {
        crate::passkey::check_create(&create)?;
        *self.choice() = None;
        self.verify_user(DomainId::Passkey)?;
        self.serve(request::Body::PasskeyCreate(create))
    }

    /// Signs with a passkey of the page. The user is verified for every
    /// request, except the one that answers a choice the user was just
    /// verified for.
    fn passkey_get(&self, get: proto::PasskeyGet) -> Reply {
        crate::passkey::check_get(&get)?;
        let answers = self
            .choice()
            .take()
            .is_some_and(|choice| choice.answered_by(&get));
        if !answers {
            self.verify_user(DomainId::Passkey)?;
        }
        let mut reply = self.serve(request::Body::PasskeyGet(get.clone()));
        if answers && matches!(&reply, Err(error) if error.code == ErrorCode::Locked as i32) {
            // The domain locked itself while the user chose: ask again.
            self.verify_user(DomainId::Passkey)?;
            reply = self.serve(request::Body::PasskeyGet(get.clone()));
        }
        if let Ok(response::Body::PasskeyChoices(choices)) = &reply {
            *self.choice() = Some(PendingChoice {
                request: get,
                choices: choices
                    .choices
                    .iter()
                    .map(|choice| choice.credential_id.clone())
                    .collect(),
                expires: Instant::now() + CHOICE_TIME,
            });
        }
        reply
    }

    fn dispatch(&self, request: request::Body) -> Reply {
        use request::Body;
        match request {
            Body::BridgeTotp(totp) => self.bridge_totp(&totp),
            Body::PasskeyCreate(create) => self.passkey_create(create),
            Body::PasskeyGet(get) => self.passkey_get(get),
            Body::Lock(lock) => {
                if lock.domain.is_none() {
                    *self.choice() = None;
                }
                self.serve(Body::Lock(lock))
            }
            Body::PairAdmit(_)
            | Body::PairJoin(_)
            | Body::PairReceiveKeys(_)
            | Body::KeyAgentAttach(_)
            | Body::ImageHostAttach(_) => Err(bad_request("this request needs a relay")),
            Body::ImageChunk(_) | Body::ImageStored(_) => {
                Err(bad_request("there is no relay on this connection"))
            }
            request => self.serve(request),
        }
    }

    /// Stores what `reply` changed before it is given; a change that cannot
    /// be stored fails the request.
    fn stored(&self, reply: response::Body) -> response::Body {
        match self.host.store(&self.service) {
            Ok(()) => reply,
            Err(error) => response::Body::Error(error),
        }
    }

    fn not_ready() -> response::Body {
        response::Body::Error(proto::Error::new(
            ErrorCode::NotReady,
            "the vault process waits for the app to attach its image host",
        ))
    }
}

impl Handler for Inner {
    fn handle(&self, _peer: &Peer, request: request::Body) -> response::Body {
        if !self.host.is_attached() {
            return Self::not_ready();
        }
        let reply = self.dispatch(request).unwrap_or_else(response::Body::Error);
        self.stored(reply)
    }

    fn starts_relay(&self, request: &request::Body) -> bool {
        matches!(
            request,
            request::Body::PairAdmit(_)
                | request::Body::PairJoin(_)
                | request::Body::PairReceiveKeys(_)
                | request::Body::KeyAgentAttach(_)
                | request::Body::ImageHostAttach(_)
        )
    }

    fn relay(&self, _peer: &Peer, request: request::Body, relay: RelayEnd) -> response::Body {
        match request {
            // Neither waits for the vault: they make it usable.
            request::Body::ImageHostAttach(_) => self.host.attach(relay, &self.service),
            request::Body::KeyAgentAttach(_) => self.agent.attach(relay),
            _ if !self.host.is_attached() => Self::not_ready(),
            request => {
                let last = self.service.relay(&request, relay);
                self.stored(last)
            }
        }
    }
}

#[cfg(test)]
mod tests;

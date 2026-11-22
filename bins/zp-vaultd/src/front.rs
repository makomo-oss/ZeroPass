//! The process the clients talk to (ADR-0007, `docs/spec/ipc.md` §5).
//!
//! It holds the password domain and nothing else. What concerns the TOTP or
//! the passkey domain it passes to that domain's worker; what needs the keys
//! of every domain at once it passes to a short-lived process, to which each
//! holder hands its key sealed. The vault keys of the hardware-bound domains
//! are therefore never in this process's memory.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;
use zp_crypto::DomainId;
use zp_ipc::proto::{self, ErrorCode, Role, new_item, request, response};
use zp_ipc::{Handler, Peer, PeerProcess, RelayEnd};

use crate::agent::AgentLink;
use crate::back::{Back, ProcessSpawner, Spawner};
use crate::convert::{self, bad_request, vault_error};
use crate::port::KeyAgentPort;
use crate::service::{KeyStoreChoice, Reply, Scope, Service, log};

/// The hardware-bound domains: each has a worker.
const WORKED: [DomainId; 2] = [DomainId::Totp, DomainId::Passkey];

/// How much longer than a pairing offer its process is kept: the offer's own
/// clock decides, this only clears up.
const OFFER_GRACE: Duration = Duration::from_secs(5);

/// How long the user has to pick one of several passkeys without being asked
/// again (`docs/spec/passkey.md` §9).
const CHOICE_TIME: Duration = Duration::from_secs(120);

/// A request for an assertion that found several passkeys, for which the
/// user was just verified: the same request, with one of them picked, is
/// signed without asking again. Nothing in it is secret.
struct PendingChoice {
    request: proto::PasskeyGet,
    choices: Vec<Vec<u8>>,
    expires: Instant,
}

impl PendingChoice {
    /// Whether `request` is the pending one with one of its passkeys picked.
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

/// The processes behind the front.
struct Backs {
    totp: Box<dyn Back>,
    passkey: Box<dyn Back>,
    /// The process that holds a pairing offer and the keys to hand over,
    /// until the offer is used or has expired.
    offer: Option<(Box<dyn Back>, Instant)>,
    /// Passkeys the user is picking from, if any.
    choice: Option<PendingChoice>,
}

impl Backs {
    fn worker(&mut self, domain: DomainId) -> Option<&mut dyn Back> {
        match domain {
            DomainId::Password => None,
            DomainId::Totp => Some(self.totp.as_mut()),
            DomainId::Passkey => Some(self.passkey.as_mut()),
        }
    }
}

/// The vault daemon as its clients see it.
pub(crate) struct Front {
    /// This process's own hold on the vault: the password domain.
    engine: Service,
    agent: Arc<AgentLink>,
    spawner: Box<dyn Spawner>,
    /// Locked for a whole request: one at a time, across all processes.
    backs: Mutex<Backs>,
}

fn done() -> Reply {
    Ok(response::Body::Done(proto::Done {}))
}

fn as_result(reply: response::Body) -> Reply {
    match reply {
        response::Body::Error(error) => Err(error),
        reply => Ok(reply),
    }
}

/// The domain a new item is stored in.
fn domain_of_new(item: Option<&proto::NewItem>) -> DomainId {
    match item.and_then(|item| item.content.as_ref()) {
        Some(new_item::Content::Totp(_)) => DomainId::Totp,
        _ => DomainId::Password,
    }
}

impl Front {
    fn build(
        path: PathBuf,
        key_store: KeyStoreChoice,
        agent: Arc<AgentLink>,
        port: Arc<dyn KeyAgentPort>,
        spawner: Box<dyn Spawner>,
    ) -> Result<Self, proto::Error> {
        Ok(Self {
            engine: Service::new(path, key_store, Scope::Front, port)?,
            backs: Mutex::new(Backs {
                totp: spawner.back(Scope::Domain(DomainId::Totp)),
                passkey: spawner.back(Scope::Domain(DomainId::Passkey)),
                offer: None,
                choice: None,
            }),
            agent,
            spawner,
        })
    }

    /// The daemon: the other processes are children of this one, started
    /// from `executable`.
    pub(crate) fn new(
        path: PathBuf,
        key_store: KeyStoreChoice,
        executable: PathBuf,
    ) -> Result<Self, proto::Error> {
        let agent = Arc::new(AgentLink::default());
        let port: Arc<dyn KeyAgentPort> = agent.clone();
        let spawner = ProcessSpawner::new(executable, path.clone(), key_store, Arc::clone(&port));
        Self::build(path, key_store, agent, port, Box::new(spawner))
    }

    /// For tests: the other processes run on threads of this one, over the
    /// same pipes, each on a vault handle of its own. Without `port`, the
    /// hardware key store is whatever key agent attaches.
    #[cfg(test)]
    pub(crate) fn local(
        path: PathBuf,
        key_store: KeyStoreChoice,
        port: Option<Arc<dyn KeyAgentPort>>,
    ) -> Self {
        let agent = Arc::new(AgentLink::default());
        let port = port.unwrap_or_else(|| agent.clone());
        let spawner = ProcessSpawner::threads(path.clone(), key_store, Arc::clone(&port));
        match Self::build(path, key_store, agent, port, Box::new(spawner)) {
            Ok(front) => front,
            Err(error) => panic!("{}", error.message),
        }
    }

    /// Whether a pairing offer waits for the other device.
    #[cfg(test)]
    pub(crate) fn offer_waits(&self) -> bool {
        self.backs().offer.is_some()
    }

    /// Lets the waiting pairing offer run out now.
    #[cfg(test)]
    pub(crate) fn expire_offer(&self) {
        if let Some((_, expires)) = self.backs().offer.as_mut() {
            *expires = Instant::now();
        }
    }

    fn backs(&self) -> MutexGuard<'_, Backs> {
        // A panic in a request must not take the daemon's other clients with it.
        self.backs
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// Called periodically: locks what has been idle for too long in this
    /// process (the workers watch their own clocks) and ends the process of
    /// a pairing offer nobody used.
    pub(crate) fn tick(&self) {
        self.engine.tick();
        // A request in progress holds the lock; the next tick will do.
        if let Ok(mut backs) = self.backs.try_lock() {
            let now = Instant::now();
            if backs
                .offer
                .as_ref()
                .is_some_and(|(_, expires)| now >= *expires)
            {
                backs.offer = None;
            }
            if backs
                .choice
                .as_ref()
                .is_some_and(|choice| now >= choice.expires)
            {
                backs.choice = None;
            }
        }
    }

    /// Wipes every key, in every process.
    #[cfg(test)]
    pub(crate) fn lock_all(&self) {
        let mut backs = self.backs();
        self.lock(&mut backs, None);
    }

    /// Ends the other processes, with whatever they hold. For when the daemon
    /// stops.
    pub(crate) fn stop(&self) {
        let mut backs = self.backs();
        self.lock(&mut backs, None);
        backs.totp.stop();
        backs.passkey.stop();
    }

    fn lock(&self, backs: &mut Backs, domain: Option<DomainId>) {
        let everything = request::Body::Lock(proto::Lock { domain: None });
        // Whatever is locked, a waiting pairing offer is withdrawn: its
        // process holds the keys of every domain. So is a pending choice of
        // passkeys: the user is asked again.
        backs.offer = None;
        backs.choice = None;
        if domain.is_none_or(|domain| domain == DomainId::Password) {
            self.engine.lock_all();
        }
        for worked in WORKED {
            if domain.is_none_or(|domain| domain == worked)
                && let Some(worker) = backs.worker(worked)
                && worker.unlocked(worked)
            {
                worker.call(everything.clone());
            }
        }
    }

    /// What the vault looks like across all processes.
    fn status(&self, backs: &mut Backs) -> Reply {
        let mut status = match self.engine.serve(request::Body::Status(proto::Status {})) {
            response::Body::Status(status) => status,
            other => return as_result(other),
        };
        for worked in WORKED {
            let wanted = convert::domain_to_proto(worked) as i32;
            let Some(entry) = status
                .domains
                .iter_mut()
                .find(|entry| entry.domain == wanted && entry.available)
            else {
                continue;
            };
            if let Some(worker) = backs.worker(worked) {
                entry.unlocked = worker.unlocked(worked);
            }
        }
        Ok(response::Body::Status(status))
    }

    /// Has the holder of `domain` answer `request`.
    fn route(&self, backs: &mut Backs, domain: DomainId, request: request::Body) -> Reply {
        match backs.worker(domain) {
            None => as_result(self.engine.serve(request)),
            Some(worker) => as_result(worker.call(request)),
        }
    }

    /// Has the holder of `domain` seal its slot key to `to`.
    fn export(
        &self,
        backs: &mut Backs,
        domain: DomainId,
        to: &[u8; zp_crypto::PUBLIC_KEY_LEN],
    ) -> Result<(u32, Vec<u8>), proto::Error> {
        match backs.worker(domain) {
            None => self.engine.export(domain, to),
            Some(worker) => {
                // A worker that is not running holds nothing; do not start
                // it to hear that.
                if !worker.unlocked(domain) {
                    return Err(convert::locked(domain));
                }
                worker.export(domain, to)
            }
        }
    }

    /// A process that holds every domain of the vault: each holder hands it
    /// its key, sealed. Fails with `Locked` for the first domain that is not
    /// unlocked.
    fn whole_with_keys(&self, backs: &mut Backs) -> Result<Box<dyn Back>, proto::Error> {
        // Find out what is locked before a process is started for nothing.
        for domain in DomainId::ALL {
            if !self.engine.has_domain(domain)? {
                continue;
            }
            let unlocked = match backs.worker(domain) {
                None => self.engine.unlocked(domain),
                Some(worker) => worker.unlocked(domain),
            };
            if !unlocked {
                return Err(convert::locked(domain));
            }
        }
        let mut whole = self.spawner.back(Scope::Whole);
        let to = whole.import_key()?;
        for domain in DomainId::ALL {
            if self.engine.has_domain(domain)? {
                let (epoch, sealed) = self.export(backs, domain, &to)?;
                whole.import(domain, epoch, sealed)?;
            }
        }
        Ok(whole)
    }

    /// After `whole` has made the vault file what it is now (created,
    /// recovered or joined): unlocks the password domain here, and hands the
    /// other domains to their workers so that the user is not asked again.
    fn adopt(
        &self,
        backs: &mut Backs,
        whole: &mut dyn Back,
        master_password: &str,
    ) -> Result<(), proto::Error> {
        self.engine.reset();
        for worked in WORKED {
            if let Some(worker) = backs.worker(worked) {
                worker.reset()?;
            }
        }
        as_result(self.engine.serve(request::Body::Unlock(proto::Unlock {
            domain: proto::Domain::Password as i32,
            master_password: master_password.to_owned(),
        })))?;
        for worked in WORKED {
            if !self.engine.has_domain(worked)? {
                continue;
            }
            let Some(worker) = backs.worker(worked) else {
                continue;
            };
            let handed = worker.import_key().and_then(|to| {
                let (epoch, sealed) = whole.export(worked, &to)?;
                worker.import(worked, epoch, sealed)
            });
            // The vault is as it should be; the domain is merely locked.
            if let Err(error) = handed {
                log(&format!(
                    "the {} domain starts locked: {}",
                    convert::domain_name(worked),
                    error.message
                ));
            }
        }
        Ok(())
    }

    fn create_vault(&self, backs: &mut Backs, request: proto::CreateVault) -> Reply {
        if self.engine.exists() {
            return Err(vault_error(zp_vault::VaultError::AlreadyExists));
        }
        let mut whole = self.spawner.back(Scope::Whole);
        let password = Zeroizing::new(request.master_password.clone());
        as_result(whole.call(request::Body::CreateVault(request)))?;
        self.adopt(backs, whole.as_mut(), &password)?;
        self.status(backs)
    }

    fn recover_vault(&self, backs: &mut Backs, request: proto::RecoverVault) -> Reply {
        // Recovery rewrites the key slots and gives this copy a new identity:
        // nothing that is open or unlocked survives it.
        self.lock(backs, None);
        let mut whole = self.spawner.back(Scope::Whole);
        let password = Zeroizing::new(request.new_master_password.clone());
        as_result(whole.call(request::Body::RecoverVault(request)))?;
        self.adopt(backs, whole.as_mut(), &password)?;
        self.status(backs)
    }

    /// The one-time code for a login of the page (`docs/spec/extension.md`
    /// §9). The user is verified anew for every code: the TOTP domain is
    /// locked and unlocked through the hardware key store, even if it was
    /// open, so that the extension cannot take codes without the user.
    fn bridge_totp(&self, backs: &mut Backs, request: &proto::BridgeTotp) -> Reply {
        self.engine
            .bridge_check(&request.origin, &request.top_origin, &request.item_id)?;
        self.verify_user(backs, DomainId::Totp)?;
        let Some(worker) = backs.worker(DomainId::Totp) else {
            return Err(bad_request("no TOTP worker"));
        };
        let list = request::Body::ListItems(proto::ListItems {
            domain: proto::Domain::Totp as i32,
            query: String::new(),
        });
        let response::Body::Items(items) = as_result(worker.call(list))? else {
            return Err(bad_request("the TOTP worker gave an unexpected answer"));
        };
        for summary in items.items {
            let get = request::Body::GetItem(proto::GetItem {
                item_id: summary.item_id.clone(),
            });
            if let response::Body::Item(proto::Item {
                content: Some(proto::item::Content::Totp(info)),
                ..
            }) = as_result(worker.call(get))?
                && info.login_id.as_deref() == Some(request.item_id.as_slice())
            {
                return as_result(worker.call(request::Body::TotpCode(proto::TotpCode {
                    item_id: summary.item_id,
                })));
            }
        }
        Err(proto::Error::new(
            ErrorCode::ItemNotFound,
            "no one-time code is tied to that login",
        ))
    }

    /// Verifies the user anew for one use of a hardware-bound domain: the
    /// domain is locked and unlocked through the hardware key store (Windows
    /// Hello), even if it was open, so that the extension cannot use it
    /// without the user.
    fn verify_user(&self, backs: &mut Backs, domain: DomainId) -> Result<(), proto::Error> {
        if !self.engine.has_domain(domain)? {
            return Err(proto::Error::about(
                ErrorCode::DomainUnavailable,
                convert::domain_to_proto(domain),
                format!(
                    "this vault has no {} domain (it was created without a hardware key store)",
                    convert::domain_name(domain)
                ),
            ));
        }
        let Some(worker) = backs.worker(domain) else {
            return Err(bad_request("that domain has no worker"));
        };
        if worker.unlocked(domain) {
            as_result(worker.call(request::Body::Lock(proto::Lock { domain: None })))?;
        }
        as_result(worker.call(request::Body::Unlock(proto::Unlock {
            domain: convert::domain_to_proto(domain) as i32,
            master_password: String::new(),
        })))
        .map(drop)
    }

    /// Makes a passkey for the page (`docs/spec/passkey.md` §9): checked
    /// here first, so that the user is not asked for a request that cannot
    /// succeed, then made in the passkey worker after the user is verified.
    fn passkey_create(&self, backs: &mut Backs, create: proto::PasskeyCreate) -> Reply {
        crate::passkey::check_create(&create)?;
        backs.choice = None;
        self.verify_user(backs, DomainId::Passkey)?;
        self.route(
            backs,
            DomainId::Passkey,
            request::Body::PasskeyCreate(create),
        )
    }

    /// Signs for the page with one of its passkeys. The user is verified for
    /// every request, except the one that answers a choice the user was just
    /// verified for.
    fn passkey_get(&self, backs: &mut Backs, get: proto::PasskeyGet) -> Reply {
        crate::passkey::check_get(&get)?;
        let answers = backs
            .choice
            .take()
            .is_some_and(|choice| choice.answered_by(&get));
        if !answers {
            self.verify_user(backs, DomainId::Passkey)?;
        }
        let mut reply = self.route(
            backs,
            DomainId::Passkey,
            request::Body::PasskeyGet(get.clone()),
        );
        if answers && matches!(&reply, Err(error) if error.code == ErrorCode::Locked as i32) {
            // The domain locked itself while the user chose: ask again.
            self.verify_user(backs, DomainId::Passkey)?;
            reply = self.route(
                backs,
                DomainId::Passkey,
                request::Body::PasskeyGet(get.clone()),
            );
        }
        if let Ok(response::Body::PasskeyChoices(choices)) = &reply {
            backs.choice = Some(PendingChoice {
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

    fn dispatch(&self, backs: &mut Backs, request: request::Body) -> Reply {
        use request::Body;
        match request {
            Body::Status(_) => self.status(backs),
            Body::CreateVault(request) => self.create_vault(backs, request),
            Body::RecoverVault(request) => self.recover_vault(backs, request),
            Body::Unlock(unlock) => {
                let domain = convert::domain_from_proto(unlock.domain)?;
                self.route(backs, domain, Body::Unlock(unlock))
            }
            Body::Lock(lock) => {
                let domain = lock.domain.map(convert::domain_from_proto).transpose()?;
                // Says so if there is no vault.
                let reply = as_result(self.engine.serve(Body::Status(proto::Status {})))?;
                if let response::Body::Status(status) = reply
                    && !status.vault_exists
                {
                    return Err(vault_error(zp_vault::VaultError::NotFound));
                }
                self.lock(backs, domain);
                done()
            }
            Body::ListItems(list) => {
                let domain = convert::domain_from_proto(list.domain)?;
                self.route(backs, domain, Body::ListItems(list))
            }
            Body::GetItem(get) => {
                let domain = self.engine.item_domain(&get.item_id)?;
                self.route(backs, domain, Body::GetItem(get))
            }
            Body::DeleteItem(delete) => {
                let domain = self.engine.item_domain(&delete.item_id)?;
                self.route(backs, domain, Body::DeleteItem(delete))
            }
            Body::AddItem(add) => {
                let domain = domain_of_new(add.item.as_ref());
                self.route(backs, domain, Body::AddItem(add))
            }
            Body::UpdateItem(update) => {
                let domain = domain_of_new(update.item.as_ref());
                self.route(backs, domain, Body::UpdateItem(update))
            }
            Body::TotpCode(code) => self.route(backs, DomainId::Totp, Body::TotpCode(code)),
            Body::BridgeTotp(totp) => self.bridge_totp(backs, &totp),
            Body::PasskeyCreate(create) => self.passkey_create(backs, create),
            Body::PasskeyGet(get) => self.passkey_get(backs, get),
            Body::CreateRecoveryKit(kit) => {
                if self.engine.has_recovery_kit()? && !kit.replace {
                    return Err(proto::Error::new(
                        ErrorCode::RecoveryKitExists,
                        "a recovery kit already exists; replacing it invalidates the old recovery key",
                    ));
                }
                let mut whole = self.whole_with_keys(backs)?;
                as_result(whole.call(Body::CreateRecoveryKit(kit)))
            }
            // Every vault key at once: in the process for the whole vault.
            body @ (Body::ExportVault(_) | Body::ImportExport(_)) => {
                let mut whole = self.whole_with_keys(backs)?;
                as_result(whole.call(body))
            }
            Body::RevokeDevice(revoke) => {
                self.engine
                    .check_revocable(&revoke.device_id, revoke.even_without_keys)?;
                let mut whole = self.whole_with_keys(backs)?;
                // The keys of every domain are replaced; each holder follows
                // from the vault file with its next use.
                as_result(whole.call(Body::RevokeDevice(revoke)))
            }
            Body::PairOffer(offer) => {
                // What is wrong with the request comes before what is locked.
                if offer
                    .hints
                    .iter()
                    .any(|hint| hint.parse::<std::net::SocketAddr>().is_err())
                {
                    return Err(bad_request("a hint is not an address and a port"));
                }
                // A new offer replaces one that is still waiting.
                backs.offer = None;
                let mut whole = self.whole_with_keys(backs)?;
                let reply = as_result(whole.call(Body::PairOffer(offer)))?;
                if let response::Body::PairOffered(offered) = &reply {
                    let lifetime = Duration::from_secs(u64::from(offered.lifetime_secs));
                    backs.offer = Some((whole, Instant::now() + lifetime + OFFER_GRACE));
                }
                Ok(reply)
            }
            Body::Shutdown(_) => {
                self.lock(backs, None);
                done()
            }
            Body::Hello(_) => Err(bad_request("Hello was already sent")),
            // These start a relay and do not arrive here.
            Body::PairAdmit(_) | Body::PairJoin(_) | Body::KeyAgentAttach(_) => {
                Err(bad_request("this request needs a relay"))
            }
            // The password domain, the registry, the sync requests, and what
            // this daemon does not answer at all.
            request => as_result(self.engine.serve(request)),
        }
    }

    fn pair_admit(&self, relay: RelayEnd) -> Reply {
        let mut backs = self.backs();
        // The offer is used up, whatever happens next.
        let Some((mut whole, _)) = backs.offer.take() else {
            return Err(proto::Error::new(
                ErrorCode::InvalidInput,
                "no pairing offer is waiting; create a new one",
            ));
        };
        as_result(whole.relay(request::Body::PairAdmit(proto::PairAdmit {}), relay))
    }

    fn pair_join(&self, join: proto::PairJoin, relay: RelayEnd) -> Reply {
        let mut backs = self.backs();
        if self.engine.exists() {
            return Err(vault_error(zp_vault::VaultError::AlreadyExists));
        }
        let mut whole = self.spawner.back(Scope::Whole);
        let password = Zeroizing::new(join.master_password.clone());
        let reply = as_result(whole.relay(request::Body::PairJoin(join), relay))?;
        self.adopt(&mut backs, whole.as_mut(), &password)?;
        Ok(reply)
    }
}

/// Whether a connection with `role` may make `request` (`docs/spec/ipc.md` §5).
fn permitted(role: Role, request: &request::Body) -> bool {
    match role {
        // Only the key agent may offer to answer for the hardware key store:
        // signatures from anyone else would open the hardware-bound domains
        // without the user.
        Role::Ui => !matches!(request, request::Body::KeyAgentAttach(_)),
        // The sync daemon moves ciphertext in and out, and nothing else.
        Role::Sync => {
            matches!(request, request::Body::Status(_)) || crate::sync::is_sync_request(request)
        }
        // The browser extension's bridge: the logins of a page, one at a
        // time (`docs/spec/extension.md` §4).
        Role::Bridge => matches!(
            request,
            request::Body::Status(_)
                | request::Body::BridgeFind(_)
                | request::Body::BridgeFill(_)
                | request::Body::BridgeTotp(_)
                | request::Body::BridgeSave(_)
                | request::Body::BridgeUpdate(_)
                | request::Body::BridgeCompare(_)
                | request::Body::PasskeyCreate(_)
                | request::Body::PasskeyGet(_)
        ),
        // What this role may ask beyond the state of the vault is defined
        // together with the agent broker (P7-01).
        Role::Broker => matches!(request, request::Body::Status(_)),
        // The key agent only answers.
        Role::KeyAgent => matches!(request, request::Body::KeyAgentAttach(_)),
        Role::Unspecified => false,
    }
}

fn denied() -> response::Body {
    response::Body::Error(proto::Error::new(
        ErrorCode::Denied,
        "this client is not allowed to make that request",
    ))
}

impl Handler for Front {
    fn handle(&self, peer: &Peer, request: request::Body) -> response::Body {
        if !permitted(peer.role, &request) {
            return denied();
        }
        let mut backs = self.backs();
        self.dispatch(&mut backs, request)
            .unwrap_or_else(response::Body::Error)
    }

    fn starts_relay(&self, request: &request::Body) -> bool {
        matches!(
            request,
            request::Body::PairAdmit(_)
                | request::Body::PairJoin(_)
                | request::Body::KeyAgentAttach(_)
        )
    }

    fn relay(&self, peer: &Peer, request: request::Body, relay: RelayEnd) -> response::Body {
        if !permitted(peer.role, &request) {
            return denied();
        }
        let outcome = match request {
            request::Body::PairAdmit(_) => self.pair_admit(relay),
            request::Body::PairJoin(join) => self.pair_join(join, relay),
            // Not behind the lock: the agent stays attached while requests
            // are answered, and answers their questions.
            request::Body::KeyAgentAttach(_) => Ok(self.agent.attach(relay)),
            _ => Err(bad_request("not a relay request")),
        };
        outcome.unwrap_or_else(response::Body::Error)
    }

    fn rejected(&self, process: &PeerProcess) {
        let who = process.executable.as_deref().map_or_else(
            || "an unidentified process".to_owned(),
            |path| path.display().to_string(),
        );
        log(&format!("refused a connection from {who}"));
    }
}

#[cfg(test)]
mod tests;

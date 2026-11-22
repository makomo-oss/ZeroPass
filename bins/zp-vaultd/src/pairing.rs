//! Pairing (`docs/spec/ipc.md` §11).
//!
//! The daemon runs the pairing protocol, because pairing hands over, or takes
//! in, every vault key. It has no connection to the other device: a client
//! relays the bytes of the link. Those bytes are the pairing channel's
//! ciphertext, so the relaying client sees neither the keys nor the grant.

use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;
use zp_crypto::DomainId;
use zp_drive::{
    DriveConfig, DriveError, Link, MemoryLink, NewVault, PairingLink, pair_as_existing,
    pair_as_new, pair_for_keys,
};
use zp_ipc::RelayEnd;
use zp_ipc::proto::{self, ErrorCode, request, response};
use zp_pairing::noise::PSK_LEN;
use zp_pairing::qr::OFFER_LIFETIME_SECS;
use zp_pairing::{Asking, Hint, Joiner, OfferRole, PairingError, PairingOffer};
use zp_sync::SessionReport;
use zp_vault::{AutoLock, CreateOptions, VaultError, default_device_name};

use crate::convert::{self, bad_request, vault_error};
use crate::service::{KeyStoreChoice, Service, State};

/// How long the user has to answer whether a device may join.
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(120);

/// An offer that was handed out and waits for the other device.
pub(crate) struct PendingOffer {
    psk: Zeroizing<[u8; PSK_LEN]>,
    expires: Instant,
    /// The idle timeouts to put back when the offer is used or has expired.
    /// While it waits, the domains must stay unlocked.
    auto_lock: AutoLock,
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// What a client is told when pairing fails.
fn drive_error(error: DriveError) -> proto::Error {
    let code = match &error {
        DriveError::Pairing(PairingError::Declined) => ErrorCode::UserCancelled,
        DriveError::Pairing(PairingError::InvalidOffer | PairingError::OfferExpired) => {
            ErrorCode::InvalidInput
        }
        // A device that is not a member, or not the one it claims to be.
        DriveError::Pairing(PairingError::UnknownPeer | PairingError::KeyMismatch) => {
            ErrorCode::Denied
        }
        _ => ErrorCode::Internal,
    };
    proto::Error::new(code, error.to_string())
}

fn done(
    device_id: &[u8],
    name: &str,
    vault_id: &[u8],
    sync: &Result<SessionReport, String>,
) -> response::Body {
    done_with(device_id, name, vault_id, sync, false, &[])
}

fn done_with(
    device_id: &[u8],
    name: &str,
    vault_id: &[u8],
    sync: &Result<SessionReport, String>,
    keys_only: bool,
    domains: &[DomainId],
) -> response::Body {
    let (first_sync_error, sent, received) = match sync {
        Ok(report) => (String::new(), report.sent, report.received.applied),
        Err(error) => (error.clone(), 0, 0),
    };
    response::Body::PairDone(proto::PairDone {
        device_id: device_id.to_vec(),
        name: name.to_owned(),
        vault_id: vault_id.to_vec(),
        first_sync_error,
        sent: sent as u64,
        received: received as u64,
        domains: domains
            .iter()
            .map(|domain| convert::domain_to_proto(*domain) as i32)
            .collect(),
        keys_only,
    })
}

/// The link for the drivers, the user's answers to confirmation requests, and
/// the way to send the client a message.
type Bridge = (Box<dyn Link>, Receiver<bool>, Sender<response::Body>);

/// The daemon's end of the relayed link, as a [`Link`] for the drivers, and
/// the user's answers to confirmation requests.
///
/// Two threads carry the bytes between the link and the relay. They end with
/// the relay: one when the client closes its uplink, the other when the
/// driver lets go of the link.
fn bridge(relay: RelayEnd) -> io::Result<Bridge> {
    let (for_driver, for_relay) = MemoryLink::pair();
    let (mut from_driver, mut to_driver) = Box::new(for_relay).split()?;
    let (confirm_tx, confirm_rx) = mpsc::channel();
    let RelayEnd { incoming, outgoing } = relay;

    // Client → driver.
    thread::spawn(move || {
        for message in incoming {
            match message {
                request::Body::LinkData(chunk) => {
                    if to_driver.write_all(&chunk.data).is_err() {
                        break;
                    }
                }
                request::Body::PairConfirm(answer) => {
                    let _ = confirm_tx.send(answer.approved);
                }
                _ => {}
            }
        }
        // Dropping `to_driver` tells the driver that the link is closed.
    });

    // Driver → client.
    let to_client = outgoing.clone();
    thread::spawn(move || {
        let mut buffer = vec![0u8; 32 * 1024];
        loop {
            match from_driver.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    let data = buffer[..n].to_vec();
                    if to_client
                        .send(response::Body::LinkData(proto::LinkData { data }))
                        .is_err()
                    {
                        break;
                    }
                }
                // Nothing to read at the moment.
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => break,
            }
        }
    });

    Ok((Box::new(for_driver), confirm_rx, outgoing))
}

impl Service {
    /// Puts the idle timeouts back that a pending offer suspended.
    fn end_offer(state: &mut State) -> Option<PendingOffer> {
        let offer = state.offer.take()?;
        if let Some(vault) = state.vault.as_mut() {
            vault.set_auto_lock(offer.auto_lock);
        }
        Some(offer)
    }

    /// Called periodically: an offer nobody used stops holding the domains
    /// unlocked.
    pub(crate) fn expire_offer(state: &mut State) {
        if state
            .offer
            .as_ref()
            .is_some_and(|offer| Instant::now() >= offer.expires)
        {
            Self::end_offer(state);
        }
    }

    /// `PairOffer`: creates the offer to show to the other device.
    pub(crate) fn pair_offer(
        &self,
        state: &mut State,
        request: &proto::PairOffer,
    ) -> Result<response::Body, proto::Error> {
        self.whole()?;
        let mut hints = Vec::with_capacity(request.hints.len());
        for hint in &request.hints {
            let address: SocketAddr = hint
                .parse()
                .map_err(|_| bad_request("a hint is not an address and a port"))?;
            hints.push(Hint::Socket(address));
        }
        // A new offer replaces one that is still waiting.
        Self::end_offer(state);
        let vault = self.vault(state)?;
        // Admitting a device hands over every vault key.
        Self::require_every_domain(vault)?;
        let key = vault.channel_key().map_err(vault_error)?;
        let offer = PairingOffer::new(OfferRole::Existing, *key.public_bytes(), hints, unix_secs())
            .map_err(|error| vault_error(VaultError::Crypto(error)))?;
        // The domains must still be unlocked when the other device has
        // connected and the user has confirmed it, which takes longer than the
        // idle timeout of the hardware-bound domains.
        let auto_lock = vault.auto_lock();
        vault.set_auto_lock(AutoLock {
            password: None,
            hardware: None,
        });
        state.offer = Some(PendingOffer {
            psk: offer.psk.clone(),
            expires: Instant::now() + Duration::from_secs(OFFER_LIFETIME_SECS),
            auto_lock,
        });
        Ok(response::Body::PairOffered(proto::PairOffered {
            offer: offer.to_text().as_str().to_owned(),
            lifetime_secs: OFFER_LIFETIME_SECS as u32,
        }))
    }

    /// `PairAdmit`: admits the device at the other end of the relayed link.
    pub(crate) fn pair_admit(&self, relay: RelayEnd) -> Result<response::Body, proto::Error> {
        self.whole()?;
        let mut state = self.state();
        let state = &mut *state;
        Self::expire_offer(state);
        // The offer is used up, whatever happens next.
        let offer = Self::end_offer(state).ok_or_else(|| {
            proto::Error::new(
                ErrorCode::InvalidInput,
                "no pairing offer is waiting; create a new one",
            )
        })?;
        let vault = self.vault(state)?;
        Self::require_every_domain(vault)?;
        let vault_id = vault.vault_id();

        let (link, answers, to_client) =
            bridge(relay).map_err(|error| drive_error(error.into()))?;
        let pairing = PairingLink {
            scanned: false,
            psk: &offer.psk,
            offered_key: None,
        };
        // Admitting takes as long as the user takes to answer: keep the
        // domains unlocked meanwhile.
        let auto_lock = vault.auto_lock();
        vault.set_auto_lock(AutoLock {
            password: None,
            hardware: None,
        });
        let admitted = pair_as_existing(
            link,
            vault,
            &pairing,
            |request| {
                let (device_id, name, keys_only) = match request {
                    Asking::Join(join) => (join.device_id, join.name.clone(), false),
                    Asking::Keys { device_id, name } => (*device_id, name.clone(), true),
                };
                let question = response::Body::PairConfirmRequest(proto::PairConfirmRequest {
                    device_id: device_id.as_bytes().to_vec(),
                    name,
                    keys_only,
                });
                if to_client.send(question).is_err() {
                    return false;
                }
                // No answer is a "no".
                answers.recv_timeout(CONFIRM_TIMEOUT).unwrap_or(false)
            },
            &DriveConfig::default(),
        );
        vault.set_auto_lock(auto_lock);
        let admitted = admitted.map_err(drive_error)?;
        Ok(done_with(
            admitted.device.as_bytes(),
            &admitted.name,
            vault_id.as_bytes(),
            &admitted.sync,
            admitted.keys_only,
            &[],
        ))
    }

    /// `PairReceiveKeys`: on a device that is already a member, asks the
    /// device at the other end of the relayed link for the TOTP and passkey
    /// keys and takes them in (ADR-0011). The key store verifies the user for
    /// a domain that is new here.
    pub(crate) fn pair_receive_keys(
        &self,
        request: &proto::PairReceiveKeys,
        relay: RelayEnd,
    ) -> Result<response::Body, proto::Error> {
        self.whole()?;
        let offer = PairingOffer::parse(&request.offer, unix_secs())
            .map_err(|error| drive_error(DriveError::Pairing(error)))?;
        if offer.role != OfferRole::Existing {
            return Err(proto::Error::new(
                ErrorCode::InvalidInput,
                "this code was not created by a device that has the vault",
            ));
        }
        let hardware = match self.hardware_or_why(true)? {
            Ok(hardware) => hardware,
            Err(why) => {
                return Err(proto::Error::new(
                    ErrorCode::HardwareUnavailable,
                    format!(
                        "the hardware key store cannot be used ({why}): set up Windows Hello \
                         (a PIN) first"
                    ),
                ));
            }
        };
        let mut state = self.state();
        let vault = self.vault(&mut state)?;
        let (link, _answers, _to_client) =
            bridge(relay).map_err(|error| drive_error(error.into()))?;
        let pairing = PairingLink {
            scanned: true,
            psk: &offer.psk,
            offered_key: Some(offer.noise_pk),
        };
        // Taking the keys in may wait for the other device's user: keep the
        // domains unlocked meanwhile.
        let auto_lock = vault.auto_lock();
        vault.set_auto_lock(AutoLock {
            password: None,
            hardware: None,
        });
        let taken = pair_for_keys(
            link,
            vault,
            &pairing,
            hardware.as_ref(),
            &DriveConfig::default(),
        );
        vault.set_auto_lock(auto_lock);
        let taken = taken.map_err(drive_error)?;
        Ok(done_with(
            vault.device_id().as_bytes(),
            "",
            vault.vault_id().as_bytes(),
            &taken.sync,
            false,
            &taken.domains,
        ))
    }

    /// `PairJoin`: creates this device's vault file from what the device at
    /// the other end of the relayed link grants.
    pub(crate) fn pair_join(
        &self,
        request: &proto::PairJoin,
        relay: RelayEnd,
    ) -> Result<response::Body, proto::Error> {
        self.whole()?;
        let mut state = self.state();
        if state.vault.is_some() || self.path.exists() {
            return Err(vault_error(VaultError::AlreadyExists));
        }
        let pairing_error = |error: PairingError| drive_error(DriveError::Pairing(error));
        let offer = PairingOffer::parse(&request.offer, unix_secs()).map_err(pairing_error)?;
        if offer.role != OfferRole::Existing {
            return Err(proto::Error::new(
                ErrorCode::InvalidInput,
                "this code was not created by a device that has the vault",
            ));
        }
        let name = if request.device_name.is_empty() {
            default_device_name()
        } else {
            request.device_name.clone()
        };
        let joiner = Joiner::new(&name).map_err(pairing_error)?;
        let hardware = self.hardware_for_new_vault(request.without_hardware)?;

        let (link, _answers, _to_client) =
            bridge(relay).map_err(|error| drive_error(error.into()))?;
        let pairing = PairingLink {
            scanned: true,
            psk: &offer.psk,
            offered_key: Some(offer.noise_pk),
        };
        let new_vault = NewVault {
            path: &self.path,
            master_password: &request.master_password,
            hardware: hardware.as_deref(),
            options: CreateOptions {
                device_name: Some(name.clone()),
                ..CreateOptions::default()
            },
        };
        let joined = match pair_as_new(link, joiner, &pairing, new_vault, &DriveConfig::default()) {
            Ok(joined) => joined,
            Err(error) => {
                if self.key_store == KeyStoreChoice::InsecureSoftware {
                    let _ = std::fs::remove_file(self.dev_key_path());
                }
                return Err(drive_error(error));
            }
        };
        let vault = state.vault.insert(joined.vault);
        Ok(done(
            vault.device_id().as_bytes(),
            &name,
            vault.vault_id().as_bytes(),
            &joined.sync,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::{Arc, Mutex};
    use std::thread::JoinHandle;

    use zp_ipc::proto::{Domain, new_item};
    use zp_ipc::{
        Client, ClientPolicy, DaemonPolicy, Endpoint, Handler, IpcError, Peer, PeerProcess, Server,
        ShutdownHandle, Uplink,
    };

    use super::*;
    use crate::front::Front;

    const PASSWORD: &str = "correct horse battery staple";
    const OTHER_PASSWORD: &str = "an entirely different passphrase";

    /// A daemon serving a vault path over the real IPC; this test binary is
    /// its user interface.
    struct Daemon {
        service: Arc<Front>,
        endpoint: Endpoint,
        shutdown: ShutdownHandle,
        serving: Option<JoinHandle<()>>,
    }

    impl Daemon {
        fn start(path: &Path) -> Self {
            Self::start_with(path, KeyStoreChoice::InsecureSoftware)
        }

        fn start_with(path: &Path, key_store: KeyStoreChoice) -> Self {
            let this = zp_ipc::current_executable().unwrap();
            let service = Arc::new(Front::local(path.to_path_buf(), key_store, None));
            let endpoint = Endpoint::for_vault(path).unwrap();
            let policy = ClientPolicy::deny_all().allow(&this, proto::Role::Ui);
            let server = Server::bind(&endpoint, policy, "test").unwrap();
            let shutdown = server.shutdown_handle();
            let serving = {
                let service = Arc::clone(&service);
                thread::spawn(move || server.serve(service))
            };
            Self {
                service,
                endpoint,
                shutdown,
                serving: Some(serving),
            }
        }

        fn connect(&self) -> Client {
            let this = zp_ipc::current_executable().unwrap();
            Client::connect(&self.endpoint, &DaemonPolicy::default().allow(this), "test").unwrap()
        }

        fn call(&self, request: request::Body) -> Result<response::Body, IpcError> {
            self.connect().call(request)
        }
    }

    impl Drop for Daemon {
        fn drop(&mut self) {
            self.shutdown.shutdown();
            if let Some(serving) = self.serving.take() {
                let _ = serving.join();
            }
        }
    }

    fn offer(daemon: &Daemon) -> String {
        match daemon
            .call(request::Body::PairOffer(proto::PairOffer { hints: vec![] }))
            .unwrap()
        {
            response::Body::PairOffered(offered) => offered.offer.clone(),
            other => panic!("unexpected answer: {other:?}"),
        }
    }

    /// Plays the two clients that relay between the devices: connects the
    /// relay of the existing device to the relay of the joining one, as if the
    /// bytes had travelled over a network, and answers the confirmation.
    fn pair(
        existing: &Daemon,
        joining: &Daemon,
        offer: &str,
        approve: bool,
    ) -> (
        Result<proto::PairDone, IpcError>,
        Result<proto::PairDone, IpcError>,
        Option<String>,
    ) {
        let join = request::Body::PairJoin(proto::PairJoin {
            offer: offer.to_owned(),
            device_name: "Test phone".into(),
            master_password: OTHER_PASSWORD.into(),
            without_hardware: false,
        });
        let (admitted, joined, asked) = relay_pairing(existing, joining, join, approve);
        (admitted, joined, asked.map(|question| question.name))
    }

    /// Like [`pair`], with any request on the other device's side, and the
    /// question the existing device's user was asked.
    fn relay_pairing(
        existing: &Daemon,
        joining: &Daemon,
        join: request::Body,
        approve: bool,
    ) -> (
        Result<proto::PairDone, IpcError>,
        Result<proto::PairDone, IpcError>,
        Option<proto::PairConfirmRequest>,
    ) {
        let (id, mut a_down) = existing
            .connect()
            .start_relay(request::Body::PairAdmit(proto::PairAdmit {}))
            .unwrap();
        let a_up = match existing.connect().attach_relay(id) {
            Ok(uplink) => Arc::new(Mutex::new(uplink)),
            // The relay is already over: the daemon refused to start. Its
            // reason is on the downlink, and the other device is never reached.
            Err(_) => {
                let refused = a_down.receive().map(|_| proto::PairDone::default());
                return (refused, Err(IpcError::NotRunning), None);
            }
        };
        let (id, mut b_down) = joining.connect().start_relay(join).unwrap();
        let mut b_up = joining.connect().attach_relay(id).unwrap();

        let send = |uplink: &Mutex<Uplink>, body: request::Body| {
            let _ = uplink.lock().unwrap().send(body);
        };
        // Existing device → joining device, and the confirmation.
        let from_existing = {
            let a_up = Arc::clone(&a_up);
            thread::spawn(move || {
                let mut asked = None;
                loop {
                    match a_down.receive() {
                        Ok(response::Body::LinkData(chunk)) => {
                            let _ = b_up.send(request::Body::LinkData(chunk));
                        }
                        Ok(response::Body::PairConfirmRequest(question)) => {
                            asked = Some(question);
                            let answer = proto::PairConfirm { approved: approve };
                            send(&a_up, request::Body::PairConfirm(answer));
                        }
                        Ok(response::Body::PairDone(done)) => return (Ok(done), asked),
                        Ok(other) => panic!("unexpected message: {other:?}"),
                        Err(error) => return (Err(error), asked),
                    }
                }
            })
        };
        // Joining device → existing device.
        let joined = loop {
            match b_down.receive() {
                Ok(response::Body::LinkData(chunk)) => {
                    send(&a_up, request::Body::LinkData(chunk));
                }
                Ok(response::Body::PairDone(done)) => break Ok(done),
                Ok(other) => panic!("unexpected message: {other:?}"),
                Err(error) => break Err(error),
            }
        };
        let (admitted, asked) = from_existing.join().unwrap();
        (admitted, joined, asked)
    }

    fn ui() -> Peer {
        Peer {
            process: PeerProcess {
                pid: None,
                executable: None,
            },
            role: proto::Role::Ui,
        }
    }

    /// A vault with one login, every domain unlocked.
    fn existing_vault(dir: &Path) -> Daemon {
        let daemon = Daemon::start(&dir.join("pc.zpvault"));
        let created = daemon.service.handle(
            &ui(),
            request::Body::CreateVault(proto::CreateVault {
                master_password: PASSWORD.into(),
                without_hardware: false,
            }),
        );
        assert!(matches!(created, response::Body::Status(_)));
        let added = daemon.service.handle(
            &ui(),
            request::Body::AddItem(proto::AddItem {
                item: Some(proto::NewItem {
                    content: Some(new_item::Content::Login(proto::Login {
                        title: "From the PC".into(),
                        username: "alice".into(),
                        password: "pc-password".into(),
                        urls: vec![],
                        notes: String::new(),
                    })),
                }),
            }),
        );
        assert!(matches!(added, response::Body::ItemAdded(_)));
        daemon
    }

    #[test]
    fn a_device_joins_through_two_daemons_and_relays() {
        let dir = tempfile::tempdir().unwrap();
        let pc = existing_vault(dir.path());
        let phone_path = dir.path().join("phone.zpvault");
        let phone = Daemon::start(&phone_path);

        let code = offer(&pc);
        let (admitted, joined, asked) = pair(&pc, &phone, &code, true);
        let admitted = admitted.unwrap();
        let joined = joined.unwrap();
        // The user was asked about the device by the name it gave.
        assert_eq!(asked.as_deref(), Some("Test phone"));
        assert_eq!(admitted.name, "Test phone");
        assert_eq!(admitted.device_id, joined.device_id);
        assert_eq!(admitted.vault_id, joined.vault_id);
        // The first sync carried the PC's login to the phone.
        assert_eq!(admitted.first_sync_error, "");
        assert_eq!(joined.first_sync_error, "");
        assert_eq!((admitted.sent, joined.received), (1, 1));

        // The phone has its own vault file, opened by its own password, with
        // every domain, and the PC's item in it.
        assert!(phone_path.exists());
        phone
            .call(request::Body::Lock(proto::Lock { domain: None }))
            .unwrap();
        let unlock = |password: &str| {
            phone.call(request::Body::Unlock(proto::Unlock {
                domain: Domain::Password as i32,
                master_password: password.into(),
            }))
        };
        assert!(unlock(PASSWORD).is_err());
        unlock(OTHER_PASSWORD).unwrap();
        match phone
            .call(request::Body::ListItems(proto::ListItems {
                domain: Domain::Password as i32,
                query: String::new(),
            }))
            .unwrap()
        {
            response::Body::Items(items) => {
                assert_eq!(items.items.len(), 1);
                assert_eq!(items.items[0].title, "From the PC");
            }
            other => panic!("unexpected answer: {other:?}"),
        }
        match phone.call(request::Body::Status(proto::Status {})).unwrap() {
            response::Body::Status(status) => {
                assert!(status.domains.iter().all(|domain| domain.available));
            }
            other => panic!("unexpected answer: {other:?}"),
        }
        // Both know two devices.
        for daemon in [&pc, &phone] {
            match daemon
                .call(request::Body::ListDevices(proto::ListDevices {}))
                .unwrap()
            {
                response::Body::Devices(devices) => assert_eq!(devices.devices.len(), 2),
                other => panic!("unexpected answer: {other:?}"),
            }
        }

        // The offer was used up: it admits nobody else.
        let other = Daemon::start(&dir.path().join("other.zpvault"));
        let (admitted, joined, _) = pair(&pc, &other, &code, true);
        assert_eq!(admitted.unwrap_err().code(), Some(ErrorCode::InvalidInput));
        assert!(joined.is_err());
        assert!(!dir.path().join("other.zpvault").exists());
    }

    fn status(daemon: &Daemon) -> proto::StatusReply {
        match daemon
            .call(request::Body::Status(proto::Status {}))
            .unwrap()
        {
            response::Body::Status(status) => status,
            other => panic!("unexpected answer: {other:?}"),
        }
    }

    /// ADR-0011: a device that joined without a key store knows that the other
    /// devices have the domains it lacks, and does not revoke them blindly.
    #[test]
    fn a_device_without_the_hardware_domains_knows_they_are_elsewhere() {
        let dir = tempfile::tempdir().unwrap();
        let pc = existing_vault(dir.path());
        let laptop = Daemon::start_with(&dir.path().join("laptop.zpvault"), KeyStoreChoice::None);
        let (admitted, joined, _) = pair(&pc, &laptop, &offer(&pc), true);
        admitted.unwrap();
        joined.unwrap();

        let states = |daemon: &Daemon| -> Vec<(bool, bool)> {
            status(daemon)
                .domains
                .iter()
                .map(|domain| (domain.available, domain.elsewhere))
                .collect()
        };
        // Password, TOTP, passkey: (here, elsewhere).
        assert_eq!(
            states(&laptop),
            [(true, false), (false, true), (false, true)]
        );
        assert_eq!(states(&pc), [(true, false); 3]);

        // Revoking the PC from the laptop would leave the TOTP and passkey keys
        // unreplaced, and lose them for good: refused unless the user insists.
        let pc_id = status(&pc).device_id;
        let revoke = |even_without_keys| {
            laptop.call(request::Body::RevokeDevice(proto::RevokeDevice {
                device_id: pc_id.clone(),
                even_without_keys,
            }))
        };
        let refused = revoke(false).unwrap_err();
        assert_eq!(refused.code(), Some(ErrorCode::KeysAtRisk));
        assert!(
            refused.to_string().contains("totp and passkey"),
            "{refused}"
        );
        revoke(true).unwrap();
    }

    /// ADR-0011 §1: a device that joined without a key store gets the TOTP and
    /// passkey keys later, through both daemons and their relays, once the
    /// PC's user agrees.
    #[test]
    fn a_device_gets_the_hardware_keys_later_through_two_daemons() {
        let dir = tempfile::tempdir().unwrap();
        let pc = existing_vault(dir.path());
        let added = pc.call(request::Body::AddItem(proto::AddItem {
            item: Some(proto::NewItem {
                content: Some(new_item::Content::Totp(proto::NewTotp {
                    otpauth_uri: "otpauth://totp/Bank:alice?secret=GEZDGNBVGY3TQOJQ".into(),
                    login_id: None,
                })),
            }),
        }));
        assert!(matches!(added, Ok(response::Body::ItemAdded(_))));
        let laptop_path = dir.path().join("laptop.zpvault");
        {
            let laptop = Daemon::start_with(&laptop_path, KeyStoreChoice::None);
            let (admitted, joined, _) = pair(&pc, &laptop, &offer(&pc), true);
            admitted.unwrap();
            joined.unwrap();
        }
        // Windows Hello is set up on the laptop now (here: the development
        // key store). Its daemon starts locked.
        let laptop = Daemon::start(&laptop_path);
        laptop
            .call(request::Body::Unlock(proto::Unlock {
                domain: Domain::Password as i32,
                master_password: OTHER_PASSWORD.into(),
            }))
            .unwrap();
        let receive =
            |offer: String| request::Body::PairReceiveKeys(proto::PairReceiveKeys { offer });
        let hardware_domains = |daemon: &Daemon| -> Vec<(bool, bool)> {
            status(daemon).domains[1..]
                .iter()
                .map(|domain| (domain.available, domain.unlocked))
                .collect()
        };

        // The PC's user refuses: nothing changes.
        let (admitted, received, asked) = relay_pairing(&pc, &laptop, receive(offer(&pc)), false);
        assert!(asked.is_some_and(|question| question.keys_only));
        assert_eq!(admitted.unwrap_err().code(), Some(ErrorCode::UserCancelled));
        assert_eq!(received.unwrap_err().code(), Some(ErrorCode::UserCancelled));
        assert_eq!(hardware_domains(&laptop), [(false, false); 2]);

        // The PC's user agrees, asked about the laptop by its registered name.
        let (admitted, received, asked) = relay_pairing(&pc, &laptop, receive(offer(&pc)), true);
        let asked = asked.unwrap();
        assert!(asked.keys_only);
        assert_eq!(asked.name, "Test phone");
        let admitted = admitted.unwrap();
        assert!(admitted.keys_only);
        let received = received.unwrap();
        assert_eq!(
            received.domains,
            [Domain::Totp as i32, Domain::Passkey as i32]
        );
        assert_eq!(hardware_domains(&laptop), [(true, true); 2]);
        assert!(
            status(&laptop)
                .domains
                .iter()
                .all(|domain| !domain.elsewhere)
        );
        // The workers hold the new domains: the PC's code is listed.
        match laptop
            .call(request::Body::ListItems(proto::ListItems {
                domain: Domain::Totp as i32,
                query: String::new(),
            }))
            .unwrap()
        {
            response::Body::Items(items) => {
                assert_eq!(items.items.len(), 1);
                assert_eq!(items.unreadable, 0);
            }
            other => panic!("unexpected answer: {other:?}"),
        }
    }

    #[test]
    fn a_declined_device_gets_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let pc = existing_vault(dir.path());
        let phone_path = dir.path().join("phone.zpvault");
        let phone = Daemon::start(&phone_path);

        let (admitted, joined, asked) = pair(&pc, &phone, &offer(&pc), false);
        assert_eq!(asked.as_deref(), Some("Test phone"));
        assert_eq!(admitted.unwrap_err().code(), Some(ErrorCode::UserCancelled));
        assert_eq!(joined.unwrap_err().code(), Some(ErrorCode::UserCancelled));
        // No vault file, no key file, and no new device on the PC.
        assert!(!phone_path.exists());
        assert!(!phone_path.with_extension("devkey").exists());
        match pc
            .call(request::Body::ListDevices(proto::ListDevices {}))
            .unwrap()
        {
            response::Body::Devices(devices) => assert_eq!(devices.devices.len(), 1),
            other => panic!("unexpected answer: {other:?}"),
        }
    }

    #[test]
    fn an_offer_needs_every_domain_and_holds_them_unlocked() {
        let dir = tempfile::tempdir().unwrap();
        let pc = existing_vault(dir.path());
        let ask = || pc.call(request::Body::PairOffer(proto::PairOffer { hints: vec![] }));

        pc.call(request::Body::Lock(proto::Lock {
            domain: Some(Domain::Totp as i32),
        }))
        .unwrap();
        let error = ask().unwrap_err();
        assert_eq!(error.code(), Some(ErrorCode::Locked));
        pc.call(request::Body::Unlock(proto::Unlock {
            domain: Domain::Totp as i32,
            master_password: String::new(),
        }))
        .unwrap();
        ask().unwrap();

        // While the offer waits, a process of its own holds the keys to hand
        // over; when it has expired, that process is gone, with the keys.
        assert!(pc.service.offer_waits());
        pc.service.expire_offer();
        pc.service.tick();
        assert!(!pc.service.offer_waits());
        let admit = pc
            .connect()
            .start_relay(request::Body::PairAdmit(proto::PairAdmit {}));
        let (_, mut downlink) = admit.unwrap();
        assert_eq!(
            downlink.receive().unwrap_err().code(),
            Some(ErrorCode::InvalidInput)
        );

        // Locking any domain withdraws an offer.
        ask().unwrap();
        assert!(pc.service.offer_waits());
        pc.call(request::Body::Lock(proto::Lock {
            domain: Some(Domain::Passkey as i32),
        }))
        .unwrap();
        assert!(!pc.service.offer_waits());

        // A hint that is not an address is refused.
        let bad = pc.call(request::Body::PairOffer(proto::PairOffer {
            hints: vec!["not an address".into()],
        }));
        assert_eq!(bad.unwrap_err().code(), Some(ErrorCode::BadRequest));
    }
}

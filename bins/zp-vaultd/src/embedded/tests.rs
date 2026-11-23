//! The embedded engine, driven like the Android app drives it: every
//! connection over a stream pair, the image host and the key agent on relays.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use zp_ipc::proto::{self, ErrorCode, IMAGE_CHUNK, new_item, request, response};
use zp_ipc::{Client, IpcError, Uplink, memory_pair};
use zp_vault::{Clock, Vault};

use super::Engine;
use crate::pairing::tests as pairing;
use crate::port::KeyAgentPort;
use crate::port::testing::FakeAgent;

const PASSWORD: &str = "the master password of the phone";

type SharedUplink = Arc<Mutex<Option<Uplink>>>;

fn send(uplink: &SharedUplink, body: request::Body) {
    if let Some(uplink) = uplink.lock().unwrap().as_mut() {
        let _ = uplink.send(body);
    }
}

/// The app process, as far as the engine sees it: connects over streams in
/// memory, stores the vault file and plays the key agent.
struct App {
    engine: Arc<Engine>,
    /// The vault file as the app stored it.
    disk: Arc<Mutex<Vec<u8>>>,
    /// Makes storing fail.
    disk_full: Arc<AtomicBool>,
    /// How many images were stored.
    stores: Arc<AtomicU32>,
    host: Option<SharedUplink>,
    agent: Option<SharedUplink>,
}

impl App {
    fn new(disk: Vec<u8>) -> Self {
        Self {
            engine: Arc::new(Engine::new()),
            disk: Arc::new(Mutex::new(disk)),
            disk_full: Arc::new(AtomicBool::new(false)),
            stores: Arc::new(AtomicU32::new(0)),
            host: None,
            agent: None,
        }
    }

    /// An app with its image host and a key agent attached.
    fn ready(disk: Vec<u8>, agent: &Arc<FakeAgent>) -> Self {
        let mut app = Self::new(disk);
        app.attach_host().unwrap();
        app.attach_agent(agent);
        app
    }

    fn connect(&self) -> Client {
        let (app_end, engine_end) = memory_pair();
        let engine = Arc::clone(&self.engine);
        thread::spawn(move || engine.converse(engine_end));
        Client::over(app_end, "test app").unwrap()
    }

    fn call(&self, body: request::Body) -> Result<response::Body, IpcError> {
        self.connect().call(body)
    }

    /// Attaches the image host: sends what is on the disk and stores what
    /// comes back. Fails with what the engine said if it did not take the
    /// image.
    fn attach_host(&mut self) -> Result<(), IpcError> {
        let (id, mut downlink) = self
            .connect()
            .start_relay(request::Body::ImageHostAttach(proto::ImageHostAttach {}))?;
        let uplink: SharedUplink = Arc::new(Mutex::new(Some(self.connect().attach_relay(id)?)));
        let image = self.disk.lock().unwrap().clone();
        if image.is_empty() {
            send(
                &uplink,
                request::Body::ImageChunk(proto::ImageChunk {
                    data: Vec::new(),
                    last: true,
                }),
            );
        }
        let mut chunks = image.chunks(IMAGE_CHUNK).peekable();
        while let Some(data) = chunks.next() {
            let chunk = proto::ImageChunk {
                data: data.to_vec(),
                last: chunks.peek().is_none(),
            };
            send(&uplink, request::Body::ImageChunk(chunk));
        }
        match downlink.receive()? {
            response::Body::Listening(_) => {}
            other => panic!("the engine did not take the image: {other:?}"),
        }
        let (disk, full, stores, up) = (
            Arc::clone(&self.disk),
            Arc::clone(&self.disk_full),
            Arc::clone(&self.stores),
            Arc::clone(&uplink),
        );
        thread::spawn(move || {
            let mut image = Vec::new();
            while let Ok(response::Body::ImageChunk(chunk)) = downlink.receive() {
                image.extend_from_slice(&chunk.data);
                if !chunk.last {
                    continue;
                }
                let error = if full.load(Ordering::SeqCst) {
                    "the disk is full".to_owned()
                } else {
                    *disk.lock().unwrap() = std::mem::take(&mut image);
                    stores.fetch_add(1, Ordering::SeqCst);
                    String::new()
                };
                image.clear();
                send(
                    &up,
                    request::Body::ImageStored(proto::ImageStored { error }),
                );
            }
        });
        self.host = Some(uplink);
        Ok(())
    }

    /// Closes the image host's uplink, as when the app goes away.
    fn detach_host(&mut self) {
        if let Some(uplink) = self.host.take() {
            uplink.lock().unwrap().take();
        }
    }

    fn attach_agent(&mut self, fake: &Arc<FakeAgent>) {
        let (id, mut downlink) = self
            .connect()
            .start_relay(request::Body::KeyAgentAttach(proto::KeyAgentAttach {}))
            .unwrap();
        let uplink: SharedUplink =
            Arc::new(Mutex::new(Some(self.connect().attach_relay(id).unwrap())));
        assert!(matches!(
            downlink.receive().unwrap(),
            response::Body::Listening(_)
        ));
        let (fake, up) = (Arc::clone(fake), Arc::clone(&uplink));
        thread::spawn(move || {
            while let Ok(response::Body::KeyAgentRequest(question)) = downlink.receive() {
                let Some(ask) = question.ask else { continue };
                let reply = proto::KeyAgentReply {
                    id: question.id,
                    outcome: Some(fake.ask(ask)),
                };
                send(&up, request::Body::KeyAgentReply(reply));
            }
        });
        self.agent = Some(uplink);
    }

    fn stores(&self) -> u32 {
        self.stores.load(Ordering::SeqCst)
    }

    fn disk(&self) -> Vec<u8> {
        self.disk.lock().unwrap().clone()
    }

    fn status(&self) -> proto::StatusReply {
        match self.call(request::Body::Status(proto::Status {})).unwrap() {
            response::Body::Status(status) => status,
            other => panic!("not a status: {other:?}"),
        }
    }

    fn create(&self) {
        let created = self
            .call(request::Body::CreateVault(proto::CreateVault {
                master_password: PASSWORD.into(),
                without_hardware: false,
                device_name: String::new(),
            }))
            .unwrap();
        assert!(matches!(created, response::Body::Status(_)));
    }

    fn add_login(&self, title: &str, password: &str) -> Result<Vec<u8>, IpcError> {
        let added = self.call(request::Body::AddItem(proto::AddItem {
            item: Some(proto::NewItem {
                content: Some(new_item::Content::Login(proto::Login {
                    title: title.into(),
                    username: "alice".into(),
                    password: password.into(),
                    urls: vec!["https://example.com".into()],
                    notes: String::new(),
                })),
            }),
        }))?;
        match added {
            response::Body::ItemAdded(added) => Ok(added.item_id),
            other => panic!("not added: {other:?}"),
        }
    }

    fn unlock_password(&self) {
        self.call(request::Body::Unlock(proto::Unlock {
            domain: proto::Domain::Password as i32,
            master_password: PASSWORD.into(),
        }))
        .unwrap();
    }

    fn titles(&self) -> Vec<String> {
        match self
            .call(request::Body::ListItems(proto::ListItems {
                domain: proto::Domain::Password as i32,
                query: String::new(),
            }))
            .unwrap()
        {
            response::Body::Items(items) => {
                items.items.into_iter().map(|item| item.title).collect()
            }
            other => panic!("not a list: {other:?}"),
        }
    }
}

fn code(result: Result<response::Body, IpcError>) -> ErrorCode {
    match result {
        Err(IpcError::Remote(error)) => ErrorCode::try_from(error.code).unwrap(),
        other => panic!("not an error from the engine: {other:?}"),
    }
}

/// Whether `needle` occurs in `haystack`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
fn nothing_is_answered_before_the_image_host_attaches() {
    let app = App::new(Vec::new());
    assert_eq!(
        code(app.call(request::Body::Status(proto::Status {}))),
        ErrorCode::NotReady
    );
    assert_eq!(
        code(app.call(request::Body::CreateVault(proto::CreateVault {
            master_password: PASSWORD.into(),
            without_hardware: true,
            device_name: String::new(),
        }))),
        ErrorCode::NotReady
    );
}

#[test]
fn every_change_is_stored_by_the_app_before_it_is_answered() {
    let agent = Arc::new(FakeAgent::new(3));
    let app = App::ready(Vec::new(), &agent);
    assert!(!app.status().vault_exists);
    assert_eq!(app.stores(), 0);

    app.create();
    assert_eq!(app.stores(), 1);
    let status = app.status();
    assert!(status.vault_exists);
    // Every domain, the hardware-bound ones through the key agent.
    assert!(status.domains.iter().all(|domain| domain.available));

    app.add_login("Example", "never-on-disk-in-the-clear")
        .unwrap();
    assert_eq!(app.stores(), 2);
    // Reading changes nothing, and nothing is stored again.
    assert_eq!(app.titles(), ["Example"]);
    app.status();
    assert_eq!(app.stores(), 2);

    // What the app stores is the vault file, with no plaintext in it.
    let disk = app.disk();
    assert!(!contains(&disk, b"never-on-disk-in-the-clear"));
    assert!(!contains(&disk, b"Example"));
    let mut vault = Vault::open_image(&disk, Clock::system()).unwrap();
    vault.unlock_password(PASSWORD).unwrap();
    assert_eq!(vault.list::<zp_crypto::Password>().unwrap().len(), 1);
}

#[test]
fn the_vault_comes_back_from_what_the_app_stored() {
    let agent = Arc::new(FakeAgent::new(3));
    let disk = {
        let app = App::ready(Vec::new(), &agent);
        app.create();
        app.add_login("Kept", "kept-password").unwrap();
        app.disk()
    };

    // A new vault process, as after Android ended the old one.
    let app = App::ready(disk, &agent);
    let status = app.status();
    assert!(status.vault_exists);
    assert!(status.domains.iter().all(|domain| !domain.unlocked));
    assert_eq!(
        code(app.call(request::Body::ListItems(proto::ListItems {
            domain: proto::Domain::Password as i32,
            query: String::new(),
        }))),
        ErrorCode::Locked
    );
    app.unlock_password();
    assert_eq!(app.titles(), ["Kept"]);

    // The hardware-bound domains open through the key agent only.
    let prompts = agent.prompts.load(Ordering::SeqCst);
    app.call(request::Body::Unlock(proto::Unlock {
        domain: proto::Domain::Totp as i32,
        master_password: String::new(),
    }))
    .unwrap();
    assert_eq!(agent.prompts.load(Ordering::SeqCst), prompts + 1);
}

#[test]
fn a_change_that_cannot_be_stored_fails() {
    let agent = Arc::new(FakeAgent::new(3));
    let app = App::ready(Vec::new(), &agent);
    app.create();
    app.unlock_password();
    let before = app.disk();

    app.disk_full.store(true, Ordering::SeqCst);
    assert_eq!(
        code(
            app.add_login("Lost", "not-stored")
                .map(|_| response::Body::Done(proto::Done {}))
        ),
        ErrorCode::Internal
    );
    assert_eq!(app.disk(), before);

    // Stored with the next change once the disk has room again.
    app.disk_full.store(false, Ordering::SeqCst);
    app.add_login("Next", "next-password").unwrap();
    let mut vault = Vault::open_image(&app.disk(), Clock::system()).unwrap();
    vault.unlock_password(PASSWORD).unwrap();
    assert_eq!(vault.list::<zp_crypto::Password>().unwrap().len(), 2);
}

#[test]
fn what_is_not_a_vault_is_refused() {
    let mut app = App::new(vec![0x42; 8192]);
    match app.attach_host() {
        Err(IpcError::Remote(error)) => assert!(
            error.message.contains("not a ZeroPass vault"),
            "{}",
            error.message
        ),
        other => panic!("the engine took it: {other:?}"),
    }
    assert_eq!(
        code(app.call(request::Body::Status(proto::Status {}))),
        ErrorCode::NotReady
    );
}

#[test]
fn when_the_app_goes_away_the_vault_is_closed() {
    let agent = Arc::new(FakeAgent::new(3));
    let mut app = App::ready(Vec::new(), &agent);
    app.create();
    app.unlock_password();
    assert_eq!(app.titles(), Vec::<String>::new());

    app.detach_host();
    let deadline = Instant::now() + Duration::from_secs(5);
    while app.call(request::Body::Status(proto::Status {})).is_ok() {
        assert!(Instant::now() < deadline, "the vault stayed open");
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        code(app.call(request::Body::Status(proto::Status {}))),
        ErrorCode::NotReady
    );

    // A new host finds the vault locked.
    app.attach_host().unwrap();
    assert!(app.status().domains.iter().all(|domain| !domain.unlocked));
}

#[test]
fn passkeys_ask_the_user_every_time() {
    let agent = Arc::new(FakeAgent::new(5));
    let app = App::ready(Vec::new(), &agent);
    app.create();
    let prompts = || agent.prompts.load(Ordering::SeqCst);
    let create = proto::PasskeyCreate {
        origin: "https://login.example.com".into(),
        top_origin: String::new(),
        rp_id: "example.com".into(),
        rp_name: "Example".into(),
        user_handle: b"alice".to_vec(),
        user_name: "alice".into(),
        user_display_name: "Alice".into(),
        challenge: b"registration challenge".to_vec(),
        algorithms: vec![-7],
        exclude: Vec::new(),
    };
    let get = |chosen: &[u8]| proto::PasskeyGet {
        origin: "https://login.example.com".into(),
        top_origin: String::new(),
        rp_id: "example.com".into(),
        challenge: b"sign-in challenge".to_vec(),
        allow: Vec::new(),
        chosen: chosen.to_vec(),
    };

    let before = prompts();
    let created = app
        .call(request::Body::PasskeyCreate(create.clone()))
        .unwrap();
    assert!(matches!(created, response::Body::PasskeyCreated(_)));
    assert_eq!(prompts(), before + 1);
    assert!(app.stores() >= 2, "the passkey was stored");

    // Even with the domain open, every assertion asks again.
    for round in 1..=2 {
        let signed = app.call(request::Body::PasskeyGet(get(&[]))).unwrap();
        assert!(matches!(signed, response::Body::PasskeyAssertion(_)));
        assert_eq!(prompts(), before + 1 + round);
    }

    // Two accounts: the choice is asked for once, the pick is not asked again.
    let bob = proto::PasskeyCreate {
        user_handle: b"bob".to_vec(),
        user_name: "bob".into(),
        ..create
    };
    app.call(request::Body::PasskeyCreate(bob)).unwrap();
    let asked = prompts();
    let response::Body::PasskeyChoices(choices) =
        app.call(request::Body::PasskeyGet(get(&[]))).unwrap()
    else {
        panic!("no choice");
    };
    assert_eq!(choices.choices.len(), 2);
    assert_eq!(prompts(), asked + 1);
    let picked = choices.choices[0].credential_id.clone();
    let signed = app.call(request::Body::PasskeyGet(get(&picked))).unwrap();
    assert!(matches!(signed, response::Body::PasskeyAssertion(_)));
    assert_eq!(prompts(), asked + 1, "the pick is not asked again");

    // Turned down: nothing.
    agent.user_present.store(false, Ordering::SeqCst);
    assert_eq!(
        code(app.call(request::Body::PasskeyGet(get(&picked)))),
        ErrorCode::UserCancelled
    );
}

#[test]
fn a_phone_joins_a_vault_through_the_app() {
    let dir = tempfile::tempdir().unwrap();
    let pc = pairing::existing_vault(dir.path());
    let code = pairing::offer(&pc);

    let agent = Arc::new(FakeAgent::new(4));
    let phone = App::ready(Vec::new(), &agent);
    let join = request::Body::PairJoin(proto::PairJoin {
        offer: code,
        device_name: "Phone".into(),
        master_password: PASSWORD.into(),
        without_hardware: false,
    });
    let (admitted, joined, asked) =
        pairing::relay_between(&|| pc.connect(), &|| phone.connect(), join, true);
    admitted.unwrap();
    let joined = joined.unwrap();
    assert!(
        joined.first_sync_error.is_empty(),
        "{}",
        joined.first_sync_error
    );
    assert_eq!(asked.unwrap().name, "Phone");

    // Stored before the relay ended, with the PC's login in it.
    let disk = phone.disk();
    assert!(!disk.is_empty());
    assert!(!dir.path().join("Phone.zpvault").exists());
    phone.unlock_password();
    assert_eq!(phone.titles(), ["From the PC"]);
    let status = phone.status();
    assert!(status.domains.iter().all(|domain| domain.available));
}

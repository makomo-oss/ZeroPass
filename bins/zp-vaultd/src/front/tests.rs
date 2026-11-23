//! What the daemon does for its clients, with every part in this process.

use super::*;
use zp_ipc::proto::{Domain as D, new_item};

const PASSWORD: &str = "correct horse battery staple";
const TOTP_URI: &str =
    "otpauth://totp/Example:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example";

struct Fixture {
    front: Front,
    _dir: tempfile::TempDir,
}

fn fixture(key_store: KeyStoreChoice) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    Fixture {
        front: Front::local(dir.path().join("test.zpvault"), key_store, None),
        _dir: dir,
    }
}

fn peer(role: Role) -> Peer {
    Peer {
        process: PeerProcess {
            pid: None,
            executable: None,
        },
        role,
    }
}

impl Fixture {
    fn call_as(&self, role: Role, request: request::Body) -> Reply {
        match self.front.handle(&peer(role), request) {
            response::Body::Error(error) => Err(error),
            reply => Ok(reply),
        }
    }

    fn call(&self, request: request::Body) -> Reply {
        self.call_as(Role::Ui, request)
    }

    fn code(&self, request: request::Body) -> ErrorCode {
        let error = self.call(request).expect_err("an error");
        ErrorCode::try_from(error.code).unwrap()
    }

    fn create(&self) {
        self.call(request::Body::CreateVault(proto::CreateVault {
            master_password: PASSWORD.into(),
            without_hardware: false,
            device_name: String::new(),
        }))
        .unwrap();
    }

    fn status(&self) -> proto::StatusReply {
        match self.call(request::Body::Status(proto::Status {})).unwrap() {
            response::Body::Status(status) => status,
            _ => panic!("not a status"),
        }
    }

    fn unlocked(&self, domain: D) -> bool {
        self.status()
            .domains
            .iter()
            .any(|status| status.domain == domain as i32 && status.unlocked)
    }

    fn lock(&self) {
        self.call(request::Body::Lock(proto::Lock { domain: None }))
            .unwrap();
    }

    fn unlock(&self, domain: D, password: &str) -> Reply {
        self.call(request::Body::Unlock(proto::Unlock {
            domain: domain as i32,
            master_password: password.into(),
        }))
    }

    fn add(&self, content: new_item::Content) -> Vec<u8> {
        let request = request::Body::AddItem(proto::AddItem {
            item: Some(proto::NewItem {
                content: Some(content),
            }),
        });
        match self.call(request).unwrap() {
            response::Body::ItemAdded(added) => added.item_id,
            _ => panic!("not added"),
        }
    }

    fn list(&self, domain: D, query: &str) -> Vec<proto::ItemSummary> {
        let request = request::Body::ListItems(proto::ListItems {
            domain: domain as i32,
            query: query.into(),
        });
        match self.call(request).unwrap() {
            response::Body::Items(items) => items.items,
            _ => panic!("not a list"),
        }
    }
}

fn login(title: &str, password: &str) -> new_item::Content {
    new_item::Content::Login(proto::Login {
        title: title.into(),
        username: "alice".into(),
        password: password.into(),
        urls: vec!["https://example.com".into()],
        notes: String::new(),
    })
}

fn get(id: &[u8]) -> request::Body {
    request::Body::GetItem(proto::GetItem {
        item_id: id.to_vec(),
    })
}

#[test]
fn a_vault_is_created_used_locked_and_unlocked() {
    let fixture = fixture(KeyStoreChoice::InsecureSoftware);
    assert!(!fixture.status().vault_exists);
    assert_eq!(fixture.code(get(&[0; 16])), ErrorCode::NoVault);

    fixture.create();
    let status = fixture.status();
    assert!(status.vault_exists);
    assert_eq!(status.vault_id.len(), 16);
    assert!(status.domains.iter().all(|d| d.available && d.unlocked));
    assert_eq!(
        fixture.code(request::Body::CreateVault(proto::CreateVault {
            master_password: PASSWORD.into(),
            without_hardware: false,
            device_name: String::new(),
        })),
        ErrorCode::VaultExists
    );

    let bank = fixture.add(login("Bank", "hunter2-hunter2"));
    fixture.add(login("Airline", "another-password"));
    fixture.add(new_item::Content::Note(proto::Note {
        title: "Wi-Fi".into(),
        body: "the passphrase".into(),
    }));
    let titles: Vec<String> = fixture
        .list(D::Password, "")
        .into_iter()
        .map(|item| item.title)
        .collect();
    assert_eq!(titles, ["Airline", "Bank", "Wi-Fi"]);
    assert_eq!(fixture.list(D::Password, "bank").len(), 1);

    match fixture.call(get(&bank)).unwrap() {
        response::Body::Item(item) => match item.content {
            Some(proto::item::Content::Login(login)) => {
                assert_eq!(login.password, "hunter2-hunter2");
            }
            _ => panic!("not a login"),
        },
        _ => panic!("not an item"),
    }

    // Locked: nothing can be read, and the error names the domain.
    fixture.lock();
    assert!(!fixture.unlocked(D::Password));
    let error = fixture.call(get(&bank)).err().unwrap();
    assert_eq!(error.code, ErrorCode::Locked as i32);
    assert_eq!(error.domain, Some(D::Password as i32));
    assert_eq!(
        fixture
            .unlock(D::Password, "not the password")
            .err()
            .unwrap()
            .code,
        ErrorCode::WrongPassword as i32
    );
    fixture.unlock(D::Password, PASSWORD).unwrap();
    assert!(fixture.unlocked(D::Password));
    // The password does not open the other domains.
    assert!(!fixture.unlocked(D::Totp));
    fixture.call(get(&bank)).unwrap();

    // Update and delete.
    fixture
        .call(request::Body::UpdateItem(proto::UpdateItem {
            item_id: bank.clone(),
            item: Some(proto::NewItem {
                content: Some(login("Bank", "a-new-password")),
            }),
        }))
        .unwrap();
    fixture
        .call(request::Body::DeleteItem(proto::DeleteItem {
            item_id: bank.clone(),
        }))
        .unwrap();
    assert_eq!(fixture.code(get(&bank)), ErrorCode::ItemNotFound);
}

#[test]
fn totp_codes_come_out_but_the_seed_does_not() {
    let fixture = fixture(KeyStoreChoice::InsecureSoftware);
    fixture.create();
    let id = fixture.add(new_item::Content::Totp(proto::NewTotp {
        otpauth_uri: TOTP_URI.into(),
        login_id: None,
    }));
    match fixture
        .call(request::Body::TotpCode(proto::TotpCode {
            item_id: id.clone(),
        }))
        .unwrap()
    {
        response::Body::TotpCode(code) => {
            assert_eq!(code.code.len(), 6);
            assert!((1..=30).contains(&code.seconds_remaining));
        }
        _ => panic!("not a code"),
    }
    match fixture.call(get(&id)).unwrap() {
        response::Body::Item(item) => {
            assert!(matches!(
                item.content,
                Some(proto::item::Content::Totp(ref info)) if info.issuer == "Example"
            ));
        }
        _ => panic!("not an item"),
    }
    assert_eq!(fixture.list(D::Totp, "").len(), 1);

    // After locking, the hardware-bound domain opens without the master
    // password (the software key store asks for nothing).
    fixture.lock();
    assert_eq!(
        fixture.code(request::Body::TotpCode(proto::TotpCode {
            item_id: id.clone()
        })),
        ErrorCode::Locked
    );
    fixture.unlock(D::Totp, "").unwrap();
    assert!(fixture.unlocked(D::Totp));
    assert!(!fixture.unlocked(D::Password));

    let bad = new_item::Content::Totp(proto::NewTotp {
        otpauth_uri: "not a uri".into(),
        login_id: None,
    });
    let request = request::Body::AddItem(proto::AddItem {
        item: Some(proto::NewItem { content: Some(bad) }),
    });
    assert_eq!(fixture.code(request), ErrorCode::InvalidInput);
}

#[test]
fn without_a_key_store_the_hardware_domains_do_not_exist() {
    let fixture = fixture(KeyStoreChoice::None);
    fixture.create();
    let status = fixture.status();
    let available: Vec<bool> = status.domains.iter().map(|d| d.available).collect();
    assert_eq!(available, [true, false, false]);
    assert_eq!(
        fixture.unlock(D::Totp, "").err().unwrap().code,
        ErrorCode::DomainUnavailable as i32
    );
    let totp = new_item::Content::Totp(proto::NewTotp {
        otpauth_uri: TOTP_URI.into(),
        login_id: None,
    });
    let request = request::Body::AddItem(proto::AddItem {
        item: Some(proto::NewItem {
            content: Some(totp),
        }),
    });
    assert_eq!(fixture.code(request), ErrorCode::DomainUnavailable);
}

#[test]
fn the_recovery_kit_needs_every_domain_and_restores_access() {
    let fixture = fixture(KeyStoreChoice::InsecureSoftware);
    fixture.create();
    let id = fixture.add(login("Bank", "hunter2-hunter2"));
    fixture.lock();
    fixture.unlock(D::Password, PASSWORD).unwrap();
    let kit = request::Body::CreateRecoveryKit(proto::CreateRecoveryKit { replace: false });
    let error = fixture.call(kit.clone()).err().unwrap();
    assert_eq!(error.code, ErrorCode::Locked as i32);
    assert_eq!(error.domain, Some(D::Totp as i32));
    fixture.unlock(D::Totp, "").unwrap();
    fixture.unlock(D::Passkey, "").unwrap();
    let recovery_key = match fixture.call(kit.clone()).unwrap() {
        response::Body::RecoveryKit(kit) => kit.recovery_key.clone(),
        _ => panic!("not a kit"),
    };
    assert!(fixture.status().has_recovery_kit);
    assert_eq!(fixture.code(kit), ErrorCode::RecoveryKitExists);

    let recover = |key: &str| {
        request::Body::RecoverVault(proto::RecoverVault {
            recovery_key: key.into(),
            new_master_password: "an entirely different passphrase".into(),
        })
    };
    assert_eq!(fixture.code(recover("garbage")), ErrorCode::InvalidInput);
    fixture.call(recover(&recovery_key)).unwrap();
    fixture.lock();
    assert_eq!(
        fixture.unlock(D::Password, PASSWORD).err().unwrap().code,
        ErrorCode::WrongPassword as i32
    );
    fixture
        .unlock(D::Password, "an entirely different passphrase")
        .unwrap();
    fixture.call(get(&id)).unwrap();
}

#[test]
fn the_master_password_can_be_changed() {
    let fixture = fixture(KeyStoreChoice::None);
    fixture.create();
    let change = |current: &str| {
        request::Body::ChangeMasterPassword(proto::ChangeMasterPassword {
            current: current.into(),
            new: "an entirely different passphrase".into(),
        })
    };
    assert_eq!(fixture.code(change("wrong")), ErrorCode::WrongPassword);
    fixture.call(change(PASSWORD)).unwrap();
    fixture.lock();
    assert!(fixture.unlock(D::Password, PASSWORD).is_err());
    fixture
        .unlock(D::Password, "an entirely different passphrase")
        .unwrap();
    let weak = request::Body::ChangeMasterPassword(proto::ChangeMasterPassword {
        current: "an entirely different passphrase".into(),
        new: "short".into(),
    });
    assert_eq!(fixture.code(weak), ErrorCode::WeakPassword);
}

#[test]
fn devices_are_listed_and_this_device_cannot_be_revoked() {
    let fixture = fixture(KeyStoreChoice::None);
    fixture.create();
    let devices = match fixture
        .call(request::Body::ListDevices(proto::ListDevices {}))
        .unwrap()
    {
        response::Body::Devices(devices) => devices.devices,
        _ => panic!("not devices"),
    };
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].state, proto::DeviceState::ThisDevice as i32);
    assert_eq!(devices[0].device_id, fixture.status().device_id);
    let revoke = |id: Vec<u8>| {
        request::Body::RevokeDevice(proto::RevokeDevice {
            device_id: id,
            even_without_keys: false,
        })
    };
    assert_eq!(
        fixture.code(revoke(devices[0].device_id.clone())),
        ErrorCode::DeviceNotFound
    );
    let unknown = vec![9; devices[0].device_id.len()];
    assert_eq!(fixture.code(revoke(unknown)), ErrorCode::DeviceNotFound);
    assert_eq!(fixture.code(revoke(vec![1, 2, 3])), ErrorCode::BadRequest);
}

#[test]
fn only_a_user_interface_may_do_more_than_ask_for_the_status() {
    let fixture = fixture(KeyStoreChoice::None);
    fixture.create();
    let id = fixture.add(login("Bank", "hunter2-hunter2"));
    for role in [Role::Bridge, Role::Broker, Role::Sync] {
        fixture
            .call_as(role, request::Body::Status(proto::Status {}))
            .unwrap();
        for request in [
            get(&id),
            request::Body::ListItems(proto::ListItems {
                domain: D::Password as i32,
                query: String::new(),
            }),
            request::Body::Lock(proto::Lock { domain: None }),
            request::Body::Shutdown(proto::Shutdown {}),
        ] {
            let error = fixture.call_as(role, request).err().unwrap();
            assert_eq!(error.code, ErrorCode::Denied as i32, "{role:?}");
        }
    }
    // Nothing was locked by the refused requests.
    assert!(fixture.unlocked(D::Password));
    assert!(
        fixture
            .call_as(Role::Unspecified, request::Body::Status(proto::Status {}))
            .is_err()
    );
}

#[test]
fn the_extension_bridge_gets_one_login_of_the_page_at_a_time() {
    let fixture = fixture(KeyStoreChoice::None);
    fixture.create();
    let bank = fixture.add(login("Bank", "hunter2-hunter2"));
    let other = fixture.add(new_item::Content::Login(proto::Login {
        title: "Other".into(),
        username: "bob".into(),
        password: "other password".into(),
        urls: vec!["https://other.test".into()],
        notes: String::new(),
    }));
    let find = |origin: &str| {
        request::Body::BridgeFind(proto::BridgeFind {
            origin: origin.into(),
            top_origin: String::new(),
        })
    };
    let fill = |origin: &str, id: &[u8]| {
        request::Body::BridgeFill(proto::BridgeFill {
            origin: origin.into(),
            top_origin: String::new(),
            item_id: id.to_vec(),
        })
    };

    let response::Body::BridgeLogins(found) = fixture
        .call_as(Role::Bridge, find("https://www.example.com"))
        .unwrap()
    else {
        panic!("not logins");
    };
    assert_eq!(found.logins.len(), 1);
    assert_eq!(found.logins[0].item_id, bank);
    assert!(!found.logins[0].exact);

    let response::Body::BridgeCredential(credential) = fixture
        .call_as(Role::Bridge, fill("https://example.com", &bank))
        .unwrap()
    else {
        panic!("not a credential");
    };
    assert_eq!(credential.password, "hunter2-hunter2");
    // Another site's login, a downgrade to http, a malformed origin.
    let code = |reply: Reply| ErrorCode::try_from(reply.err().unwrap().code).unwrap();
    assert_eq!(
        code(fixture.call_as(Role::Bridge, fill("https://example.com", &other))),
        ErrorCode::Denied
    );
    assert_eq!(
        code(fixture.call_as(Role::Bridge, fill("http://example.com", &bank))),
        ErrorCode::Denied
    );
    assert_eq!(
        code(fixture.call_as(Role::Bridge, find("example.com"))),
        ErrorCode::BadRequest
    );
    // In a frame of another site: nothing is offered or handed out; in a
    // frame of the same site, as on the page itself.
    let framed = request::Body::BridgeFind(proto::BridgeFind {
        origin: "https://example.com".into(),
        top_origin: "https://evil.test".into(),
    });
    let response::Body::BridgeLogins(none) = fixture.call_as(Role::Bridge, framed).unwrap() else {
        panic!("not logins");
    };
    assert!(none.logins.is_empty());
    let framed_fill = |top: &str| {
        request::Body::BridgeFill(proto::BridgeFill {
            origin: "https://example.com".into(),
            item_id: bank.clone(),
            top_origin: top.into(),
        })
    };
    assert_eq!(
        code(fixture.call_as(Role::Bridge, framed_fill("https://evil.test"))),
        ErrorCode::Denied
    );
    fixture
        .call_as(Role::Bridge, framed_fill("https://www.example.com"))
        .unwrap();
    // The bridge cannot unlock; once locked it is told so.
    assert_eq!(
        code(fixture.call_as(
            Role::Bridge,
            request::Body::Unlock(proto::Unlock {
                domain: D::Password as i32,
                master_password: PASSWORD.into(),
            })
        )),
        ErrorCode::Denied
    );
    fixture.lock();
    assert_eq!(
        code(fixture.call_as(Role::Bridge, find("https://example.com"))),
        ErrorCode::Locked
    );
    // No other role may ask what the bridge asks.
    for role in [Role::Broker, Role::Sync, Role::KeyAgent] {
        assert_eq!(
            code(fixture.call_as(role, find("https://example.com"))),
            ErrorCode::Denied,
            "{role:?}"
        );
    }
}

/// The sync daemon's view of the vault, over the real IPC, shows what the
/// vault file holds, and what it hands in is checked like any peer's data.
#[test]
fn the_sync_daemon_reads_and_writes_ops_through_the_ipc() {
    use std::sync::Arc;
    use zp_ipc::{Client, ClientPolicy, DaemonPolicy, Endpoint, RemoteOpLog, Server};
    use zp_sync::OpLog;
    use zp_vault::Store;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.zpvault");
    let service = Arc::new(Front::local(path.clone(), KeyStoreChoice::None, None));
    let ui = peer(Role::Ui);
    let created = service.handle(
        &ui,
        request::Body::CreateVault(proto::CreateVault {
            master_password: PASSWORD.into(),
            without_hardware: false,
            device_name: String::new(),
        }),
    );
    assert!(matches!(created, response::Body::Status(_)));
    for title in ["One", "Two", "Three"] {
        let added = service.handle(
            &ui,
            request::Body::AddItem(proto::AddItem {
                item: Some(proto::NewItem {
                    content: Some(login(title, "a-password")),
                }),
            }),
        );
        assert!(matches!(added, response::Body::ItemAdded(_)));
    }
    // The sync daemon works on the locked vault.
    service.lock_all();

    // This test binary plays the sync daemon.
    let this = std::env::current_exe().unwrap();
    let endpoint = Endpoint::for_vault(&path).unwrap();
    let policy = ClientPolicy::deny_all().allow(&this, Role::Sync);
    let server = Server::bind(&endpoint, policy, "test").unwrap();
    let shutdown = server.shutdown_handle();
    let serving = {
        let service = Arc::clone(&service);
        std::thread::spawn(move || server.serve(service))
    };
    let client =
        Client::connect(&endpoint, &DaemonPolicy::default().allow(&this), "syncd").unwrap();
    let mut remote = RemoteOpLog::new(client).unwrap();

    let store = Store::open(&path).unwrap();
    assert_eq!(remote.vault_id(), store.vault_id());
    assert_eq!(remote.device_id(), store.device_id());
    assert_eq!(
        remote.channel_key().public_bytes(),
        store.channel_key().unwrap().public_bytes()
    );
    let own = store.device_id();
    let vector = remote.version_vector().unwrap();
    assert_eq!(vector, store.version_vector().unwrap());
    assert_eq!(vector.get(&own), 3);
    let registry = remote.registry().unwrap();
    assert_eq!(registry.records().count(), 1);
    assert!(registry.is_active(&own));

    let ops = remote.ops_after(own, 0, 100).unwrap();
    assert_eq!(ops, store.ops_after(own, 0, 100).unwrap());
    assert_eq!(ops.len(), 3);
    assert_eq!(remote.ops_after(own, 2, 100).unwrap().len(), 1);
    assert_eq!(remote.ops_after(own, 0, 2).unwrap().len(), 2);
    assert_eq!(remote.key_updates().unwrap().len(), 0);

    // Handing in what is already there changes nothing.
    let report = remote.apply(ops.clone()).unwrap();
    assert_eq!((report.applied, report.duplicates), (0, 3));
    let records: Vec<_> = registry.records().cloned().collect();
    assert!(!remote.merge_registry(records, Vec::new()).unwrap());
    assert_eq!(remote.merge_key_updates(Vec::new()).unwrap(), 0);

    // An op that was tampered with is refused, and nothing is stored.
    let mut forged = ops[2].clone();
    forged.body.seq = 4;
    let error = remote.apply(vec![forged]).unwrap_err();
    match error {
        zp_ipc::RemoteSyncError::Ipc(error) => {
            assert_eq!(error.code(), Some(ErrorCode::SyncRejected), "{error}");
        }
        other => panic!("unexpected error: {other}"),
    }
    assert_eq!(remote.version_vector().unwrap().get(&own), 3);

    drop(remote);
    shutdown.shutdown();
    serving.join().unwrap();
}

#[test]
fn the_sync_daemon_cannot_read_items_and_others_cannot_sync() {
    let fixture = fixture(KeyStoreChoice::None);
    fixture.create();
    let sync = || request::Body::SyncVector(proto::SyncVector {});
    fixture.call_as(Role::Sync, sync()).unwrap();
    fixture.call_as(Role::Ui, sync()).unwrap();
    for role in [Role::Bridge, Role::Broker] {
        let error = fixture.call_as(role, sync()).err().unwrap();
        assert_eq!(error.code, ErrorCode::Denied as i32);
    }
    // Malformed sync data is the sender's fault.
    let garbage = request::Body::SyncApply(proto::SyncApply { ops: vec![0xFF; 8] });
    let error = fixture.call_as(Role::Sync, garbage).err().unwrap();
    assert_eq!(error.code, ErrorCode::SyncRejected as i32);
}

#[test]
fn shutdown_locks_everything() {
    let fixture = fixture(KeyStoreChoice::None);
    fixture.create();
    fixture
        .call(request::Body::Shutdown(proto::Shutdown {}))
        .unwrap();
    assert!(!fixture.unlocked(D::Password));
}

#[test]
fn idle_domains_are_locked_by_the_tick() {
    let fixture = fixture(KeyStoreChoice::None);
    fixture.create();
    {
        let mut state = fixture.front.engine.state();
        let vault = state.vault.as_mut().unwrap();
        vault.set_auto_lock(zp_vault::AutoLock {
            password: Some(std::time::Duration::ZERO),
            hardware: None,
        });
        // `set_auto_lock` applies the timeout at once; unlock again so that
        // the tick has something to do.
        vault.unlock_password(PASSWORD).unwrap();
    }
    fixture.front.tick();
    let state = fixture.front.engine.state();
    assert!(format!("{:?}", state.vault).contains("unlocked: []"));
}

#[test]
fn every_one_time_code_through_the_bridge_asks_the_user_again() {
    use std::sync::atomic::Ordering;

    use crate::port::testing::FakeAgent;

    let dir = tempfile::tempdir().unwrap();
    let agent = Arc::new(FakeAgent::new(5));
    let port: Arc<dyn crate::port::KeyAgentPort> = agent.clone();
    let fixture = Fixture {
        front: Front::local(
            dir.path().join("test.zpvault"),
            KeyStoreChoice::Platform,
            Some(port),
        ),
        _dir: dir,
    };
    fixture.create();
    let bank = fixture.add(login("Bank", "hunter2-hunter2"));
    let other = fixture.add(new_item::Content::Login(proto::Login {
        title: "Other".into(),
        username: "bob".into(),
        password: "other password".into(),
        urls: vec!["https://example.com/other".into()],
        notes: String::new(),
    }));
    fixture.add(new_item::Content::Totp(proto::NewTotp {
        otpauth_uri: "otpauth://totp/Bank:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
        login_id: Some(bank.clone()),
    }));
    let totp = |id: &[u8], origin: &str| {
        request::Body::BridgeTotp(proto::BridgeTotp {
            origin: origin.into(),
            top_origin: String::new(),
            item_id: id.to_vec(),
        })
    };
    let code = |reply: Reply| ErrorCode::try_from(reply.err().unwrap().code).unwrap();

    // The TOTP domain is open (the vault was just made), yet each code asks.
    assert!(fixture.unlocked(D::Totp));
    let before = agent.prompts.load(Ordering::SeqCst);
    for round in 1..=2 {
        let response::Body::TotpCode(reply) = fixture
            .call_as(Role::Bridge, totp(&bank, "https://example.com"))
            .unwrap()
        else {
            panic!("not a code");
        };
        assert_eq!(reply.code.len(), 6);
        assert_eq!(agent.prompts.load(Ordering::SeqCst), before + round);
    }
    // A cancelled prompt gives no code.
    agent.user_present.store(false, Ordering::SeqCst);
    assert_eq!(
        code(fixture.call_as(Role::Bridge, totp(&bank, "https://example.com"))),
        ErrorCode::UserCancelled
    );
    agent.user_present.store(true, Ordering::SeqCst);
    // Not for another site's page, and not without a code tied to the login.
    let prompts = agent.prompts.load(Ordering::SeqCst);
    assert_eq!(
        code(fixture.call_as(Role::Bridge, totp(&bank, "https://evil.test"))),
        ErrorCode::Denied
    );
    assert_eq!(
        agent.prompts.load(Ordering::SeqCst),
        prompts,
        "asked for nothing"
    );
    assert_eq!(
        code(fixture.call_as(Role::Bridge, totp(&other, "https://example.com"))),
        ErrorCode::ItemNotFound
    );
}

#[test]
fn the_bridge_saves_compares_and_updates_logins_of_the_page() {
    let fixture = fixture(KeyStoreChoice::None);
    fixture.create();
    let compare = |username: &str, password: &str| {
        let request = request::Body::BridgeCompare(proto::BridgeCompare {
            origin: "https://login.example.com".into(),
            top_origin: String::new(),
            username: username.into(),
            password: password.into(),
        });
        match fixture.call_as(Role::Bridge, request).unwrap() {
            response::Body::BridgeComparison(comparison) => comparison,
            _ => panic!("not a comparison"),
        }
    };
    // Nothing yet: a new login.
    assert!(compare("alice", "first password").item_id.is_empty());
    let saved = fixture
        .call_as(
            Role::Bridge,
            request::Body::BridgeSave(proto::BridgeSave {
                origin: "https://login.example.com".into(),
                top_origin: String::new(),
                title: String::new(),
                username: "alice".into(),
                password: "first password".into(),
            }),
        )
        .unwrap();
    let response::Body::ItemAdded(added) = saved else {
        panic!("not added");
    };
    // Saved with the page's origin and a title from its host.
    let response::Body::Item(item) = fixture.call(get(&added.item_id)).unwrap() else {
        panic!("not an item");
    };
    let Some(proto::item::Content::Login(login)) = item.content else {
        panic!("not a login");
    };
    assert_eq!(login.title, "login.example.com");
    assert_eq!(login.urls, ["https://login.example.com"]);

    let same = compare("alice", "first password");
    assert_eq!(
        (same.item_id.as_slice(), same.same),
        (added.item_id.as_slice(), true)
    );
    let changed = compare("alice", "second password");
    assert_eq!(
        (changed.item_id.as_slice(), changed.same),
        (added.item_id.as_slice(), false)
    );
    assert!(compare("bob", "first password").item_id.is_empty());

    let update = |origin: &str| {
        request::Body::BridgeUpdate(proto::BridgeUpdate {
            origin: origin.into(),
            top_origin: String::new(),
            item_id: added.item_id.clone(),
            password: "second password".into(),
        })
    };
    let refused = fixture.call_as(Role::Bridge, update("https://evil.test"));
    assert_eq!(refused.err().unwrap().code, ErrorCode::Denied as i32);
    fixture
        .call_as(Role::Bridge, update("https://login.example.com"))
        .unwrap();
    assert!(compare("alice", "second password").same);
    // The same account, typed with other capitals.
    let capitals = compare(" Alice ", "second password");
    assert_eq!(
        (capitals.item_id.as_slice(), capitals.same),
        (added.item_id.as_slice(), true)
    );
    // A page that asks for the password only (it remembers who signs in):
    // the login with that password is the one, and nothing is offered.
    let unnamed = compare("", "second password");
    assert!(unnamed.same && unnamed.item_id.is_empty());
    // Another password there: which login changed cannot be told, and no
    // login is to be overwritten by guessing.
    let unknown = compare("", "some other password");
    assert!(unknown.same && unknown.item_id.is_empty());
    // A page without logins still gets the offer to save.
    let elsewhere = request::Body::BridgeCompare(proto::BridgeCompare {
        origin: "https://other.test".into(),
        top_origin: String::new(),
        username: String::new(),
        password: "a password".into(),
    });
    let response::Body::BridgeComparison(fresh) = fixture.call_as(Role::Bridge, elsewhere).unwrap()
    else {
        panic!("not a comparison");
    };
    assert!(!fresh.same && fresh.item_id.is_empty());
    // A login saved without a user name is found again once the user name
    // shows.
    fixture
        .call_as(
            Role::Bridge,
            request::Body::BridgeSave(proto::BridgeSave {
                origin: "https://login.example.com".into(),
                top_origin: String::new(),
                title: String::new(),
                username: String::new(),
                password: "unnamed password".into(),
            }),
        )
        .unwrap();
    assert!(compare("carol", "unnamed password").same);
    assert!(!compare("carol", "carol password").same);
    // A frame of another site may do none of it.
    let framed = request::Body::BridgeSave(proto::BridgeSave {
        origin: "https://login.example.com".into(),
        top_origin: "https://evil.test".into(),
        title: String::new(),
        username: "mallory".into(),
        password: "x".into(),
    });
    assert_eq!(
        fixture.call_as(Role::Bridge, framed).err().unwrap().code,
        ErrorCode::Denied as i32
    );
}

#[test]
fn passkeys_are_made_and_used_through_the_bridge_with_the_user_each_time() {
    use std::sync::atomic::Ordering;

    use crate::port::testing::FakeAgent;

    let dir = tempfile::tempdir().unwrap();
    let agent = Arc::new(FakeAgent::new(9));
    let port: Arc<dyn crate::port::KeyAgentPort> = agent.clone();
    let fixture = Fixture {
        front: Front::local(
            dir.path().join("test.zpvault"),
            KeyStoreChoice::Platform,
            Some(port),
        ),
        _dir: dir,
    };
    fixture.create();
    let prompts = || agent.prompts.load(Ordering::SeqCst);
    let bridge = |request: request::Body| fixture.call_as(Role::Bridge, request);
    let code = |reply: Reply| ErrorCode::try_from(reply.err().unwrap().code).unwrap();
    let create = |user: &[u8], name: &str| proto::PasskeyCreate {
        origin: "https://login.example.com".into(),
        top_origin: String::new(),
        rp_id: "example.com".into(),
        rp_name: "Example".into(),
        user_handle: user.to_vec(),
        user_name: name.into(),
        user_display_name: name.into(),
        challenge: b"registration challenge".to_vec(),
        algorithms: vec![-7],
        exclude: Vec::new(),
        client_data_hash: Vec::new(),
    };
    let get = |chosen: &[u8]| proto::PasskeyGet {
        origin: "https://login.example.com".into(),
        top_origin: String::new(),
        rp_id: "example.com".into(),
        challenge: b"sign-in challenge".to_vec(),
        allow: Vec::new(),
        chosen: chosen.to_vec(),
        client_data_hash: Vec::new(),
        list_only: false,
    };
    let created = |reply: Reply| match reply.unwrap() {
        response::Body::PasskeyCreated(created) => created,
        other => panic!("not created: {other:?}"),
    };
    let asserted = |reply: Reply| match reply.unwrap() {
        response::Body::PasskeyAssertion(assertion) => assertion,
        other => panic!("not an assertion: {other:?}"),
    };

    // Made in the passkey worker, after the user was asked: the domain was
    // open (the vault was just made), yet the user is asked.
    assert!(fixture.unlocked(D::Passkey));
    let before = prompts();
    let alice = created(bridge(request::Body::PasskeyCreate(create(
        b"alice", "alice",
    ))));
    assert_eq!(prompts(), before + 1);
    assert_eq!(alice.algorithm, -7);
    let listed = fixture.list(D::Passkey, "");
    assert_eq!(listed.len(), 1);
    assert_eq!(
        (listed[0].title.as_str(), listed[0].username.as_str()),
        ("example.com", "alice")
    );

    // Signed with it, after the user was asked again.
    let assertion = asserted(bridge(request::Body::PasskeyGet(get(&[]))));
    assert_eq!(prompts(), before + 2);
    assert_eq!(assertion.credential_id, alice.credential_id);
    assert_eq!(assertion.user_handle, b"alice");
    assert!(zp_passkey::authenticator::verify(
        &alice.public_key,
        &assertion.authenticator_data,
        &assertion.client_data_json,
        &assertion.signature
    ));

    // Two accounts: the user is asked, chooses, and is not asked again for
    // that request; another request asks again.
    let bob = created(bridge(request::Body::PasskeyCreate(create(b"bob", "bob"))));
    let asked = prompts();
    let response::Body::PasskeyChoices(choices) =
        bridge(request::Body::PasskeyGet(get(&[]))).unwrap()
    else {
        panic!("a choice");
    };
    assert_eq!(prompts(), asked + 1);
    let names: Vec<&str> = choices
        .choices
        .iter()
        .map(|c| c.user_name.as_str())
        .collect();
    assert_eq!(names, ["alice", "bob"]);
    let picked = asserted(bridge(request::Body::PasskeyGet(get(&bob.credential_id))));
    assert_eq!(prompts(), asked + 1, "the pick is not asked again");
    assert_eq!(picked.user_handle, b"bob");
    let again = asserted(bridge(request::Body::PasskeyGet(get(&bob.credential_id))));
    assert_eq!(again.user_handle, b"bob");
    assert_eq!(prompts(), asked + 2, "the choice is used up");
    // A pick for another challenge is a new request: asked.
    bridge(request::Body::PasskeyGet(get(&[]))).unwrap();
    let other = proto::PasskeyGet {
        challenge: b"another challenge".to_vec(),
        ..get(&alice.credential_id)
    };
    let before_other = prompts();
    asserted(bridge(request::Body::PasskeyGet(other)));
    assert_eq!(prompts(), before_other + 1);

    // The user says no: nothing is made or signed.
    agent.user_present.store(false, Ordering::SeqCst);
    assert_eq!(
        code(bridge(request::Body::PasskeyCreate(create(
            b"carol", "carol"
        )))),
        ErrorCode::UserCancelled
    );
    assert_eq!(
        code(bridge(request::Body::PasskeyGet(get(&[])))),
        ErrorCode::UserCancelled
    );
    agent.user_present.store(true, Ordering::SeqCst);

    // What cannot succeed is refused before the user is asked.
    let quiet = prompts();
    let elsewhere = proto::PasskeyCreate {
        origin: "https://example.com.evil.net".into(),
        ..create(b"mallory", "mallory")
    };
    assert_eq!(
        code(bridge(request::Body::PasskeyCreate(elsewhere))),
        ErrorCode::Denied
    );
    let framed = proto::PasskeyGet {
        top_origin: "https://evil.net".into(),
        ..get(&[])
    };
    assert_eq!(
        code(bridge(request::Body::PasskeyGet(framed))),
        ErrorCode::Denied
    );
    let rsa = proto::PasskeyCreate {
        algorithms: vec![-257],
        ..create(b"dave", "dave")
    };
    assert_eq!(
        code(bridge(request::Body::PasskeyCreate(rsa))),
        ErrorCode::UnsupportedAlgorithm
    );
    assert_eq!(prompts(), quiet, "asked for nothing");

    // An excluded credential, a site without passkeys.
    let excluded = proto::PasskeyCreate {
        exclude: vec![alice.credential_id.clone()],
        ..create(b"alice-2", "alice")
    };
    assert_eq!(
        code(bridge(request::Body::PasskeyCreate(excluded))),
        ErrorCode::CredentialExcluded
    );
    let nothing = proto::PasskeyGet {
        origin: "https://example.net".into(),
        rp_id: String::new(),
        ..get(&[])
    };
    assert_eq!(
        code(bridge(request::Body::PasskeyGet(nothing))),
        ErrorCode::ItemNotFound
    );

    // Neither the agent broker nor the sync daemon may, and the front itself
    // cannot: it never holds the passkey domain.
    for role in [Role::Broker, Role::Sync] {
        assert_eq!(
            ErrorCode::try_from(
                fixture
                    .call_as(role, request::Body::PasskeyGet(get(&[])))
                    .err()
                    .unwrap()
                    .code
            )
            .unwrap(),
            ErrorCode::Denied
        );
    }
    let response::Body::Error(error) = fixture
        .front
        .engine
        .serve(request::Body::PasskeyGet(get(&[])))
    else {
        panic!("the front answered");
    };
    assert_eq!(error.code, ErrorCode::Internal as i32);
}

/// ADR-0011: without a usable Windows Hello, a vault is made only when the
/// user chose to go on without it.
#[test]
fn without_windows_hello_a_vault_is_made_only_if_the_user_says_so() {
    use std::sync::atomic::Ordering;

    use crate::port::testing::FakeAgent;

    let dir = tempfile::tempdir().unwrap();
    let agent = Arc::new(FakeAgent::new(3));
    agent.available.store(false, Ordering::SeqCst);
    let port: Arc<dyn crate::port::KeyAgentPort> = agent.clone();
    let fixture = Fixture {
        front: Front::local(
            dir.path().join("test.zpvault"),
            KeyStoreChoice::Platform,
            Some(port),
        ),
        _dir: dir,
    };
    let create = |without_hardware| {
        request::Body::CreateVault(proto::CreateVault {
            master_password: PASSWORD.into(),
            without_hardware,
            device_name: String::new(),
        })
    };
    assert_eq!(fixture.code(create(false)), ErrorCode::HardwareUnavailable);
    assert!(!fixture.status().vault_exists);

    fixture.call(create(true)).unwrap();
    let status = fixture.status();
    let available: Vec<bool> = status.domains.iter().map(|d| d.available).collect();
    assert_eq!(available, [true, false, false]);
    // No other device has them either: they are to be made here later.
    assert!(status.domains.iter().all(|d| !d.elsewhere));
}

/// ADR-0011 §2: a vault made without Windows Hello gets its one-time code
/// domain once Windows Hello is there; the worker serves it without asking
/// again.
#[test]
fn a_domain_is_set_up_later_and_served_by_its_worker() {
    use std::sync::atomic::Ordering;

    use crate::port::testing::FakeAgent;

    let dir = tempfile::tempdir().unwrap();
    let agent = Arc::new(FakeAgent::new(4));
    agent.available.store(false, Ordering::SeqCst);
    let port: Arc<dyn crate::port::KeyAgentPort> = agent.clone();
    let fixture = Fixture {
        front: Front::local(
            dir.path().join("test.zpvault"),
            KeyStoreChoice::Platform,
            Some(port),
        ),
        _dir: dir,
    };
    fixture
        .call(request::Body::CreateVault(proto::CreateVault {
            master_password: PASSWORD.into(),
            without_hardware: true,
            device_name: String::new(),
        }))
        .unwrap();
    let set_up = |domain: D| {
        request::Body::SetUpDomain(proto::SetUpDomain {
            domain: domain as i32,
        })
    };
    // Still no Windows Hello: nothing changes.
    assert_eq!(
        fixture.code(set_up(D::Totp)),
        ErrorCode::HardwareUnavailable
    );
    agent.available.store(true, Ordering::SeqCst);
    // The password domain holds the device signing key.
    fixture.lock();
    assert_eq!(fixture.code(set_up(D::Totp)), ErrorCode::Locked);
    fixture.unlock(D::Password, PASSWORD).unwrap();
    assert_eq!(fixture.code(set_up(D::Password)), ErrorCode::BadRequest);

    let prompts = agent.prompts.load(Ordering::SeqCst);
    let response::Body::Status(status) = fixture.call(set_up(D::Totp)).unwrap() else {
        panic!("not a status");
    };
    assert!(
        agent.prompts.load(Ordering::SeqCst) > prompts,
        "Hello was not asked"
    );
    let totp = status.domains[1];
    assert!(totp.available && totp.unlocked && !totp.elsewhere);
    assert!(!status.domains[2].available);
    assert_eq!(fixture.code(set_up(D::Totp)), ErrorCode::InvalidInput);

    // The worker holds the new domain: a code without asking again.
    let prompts = agent.prompts.load(Ordering::SeqCst);
    let id = fixture.add(new_item::Content::Totp(proto::NewTotp {
        otpauth_uri: TOTP_URI.into(),
        login_id: None,
    }));
    let response::Body::TotpCode(code) = fixture
        .call(request::Body::TotpCode(proto::TotpCode { item_id: id }))
        .unwrap()
    else {
        panic!("not a code");
    };
    assert_eq!(code.code.len(), 6);
    assert_eq!(agent.prompts.load(Ordering::SeqCst), prompts);
    assert_eq!(fixture.list(D::Totp, "").len(), 1);
}

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
    let revoke = |id: Vec<u8>| request::Body::RevokeDevice(proto::RevokeDevice { device_id: id });
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

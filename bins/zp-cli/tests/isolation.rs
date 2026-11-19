//! Where the vault keys are (ADR-0007): the acceptance test of the split into
//! one process per key domain. Runs the real daemon, in its sandbox where the
//! platform has one, and reads the memory of its processes the way a program
//! of the same user could.

#![allow(clippy::unwrap_used, reason = "test helpers may panic")]

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use zp_crypto::{InsecureSoftwareKeyStore, Passkey, Password, Totp};
use zp_vault::Vault;
use zp_vault::model::PasskeyCredential;

mod common;

const PASSWORD: &str = "correct horse battery staple";
/// The RFC 6238 SHA-1 test secret: the seed is `12345678901234567890`.
const TOTP_URI: &str =
    "otpauth://totp/Example:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example";
const TOTP_SEED: &[u8] = b"12345678901234567890";
/// The same seed as it travels from the client: base32, inside the URI.
const TOTP_SEED_BASE32: &[u8] = b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

/// Runs `zp-cli` for `vault`; each element of `input` answers one prompt.
fn cli(vault: &Path, args: &[&str], input: &[&str]) -> String {
    let mut child = Command::new(env!("CARGO_BIN_EXE_zp-cli"))
        .arg("--vault")
        .arg(vault)
        .arg("--insecure-software-keystore")
        .args(args)
        .env_remove("ZEROPASS_VAULT")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    for line in input {
        // The CLI may not need every answer.
        if writeln!(stdin, "{line}").is_err() {
            break;
        }
    }
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

/// The process the clients talk to, from `daemon status`.
fn front_process(vault: &Path) -> u32 {
    let status = cli(vault, &["daemon", "status"], &[]);
    status
        .lines()
        .find_map(|line| line.trim().strip_prefix("process: "))
        .and_then(|pid| pid.trim().parse().ok())
        .unwrap_or_else(|| panic!("no process id in: {status}"))
}

/// The processes `parent` started.
fn children_of(parent: u32) -> Vec<u32> {
    let query = format!(
        "Get-CimInstance Win32_Process -Filter \"ParentProcessId={parent}\" | \
         ForEach-Object {{ $_.ProcessId }}"
    );
    let output = Command::new("powershell")
        .args(["-NoProfile", "-Command", &query])
        .output()
        .unwrap();
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.trim().parse().ok())
        .collect()
}

fn contains(pid: u32, needle: &[u8]) -> bool {
    zp_sandbox::memory_contains(pid, needle)
        .expect("checked by the caller")
        .unwrap_or_else(|error| panic!("cannot read the memory of process {pid}: {error}"))
}

#[test]
fn the_keys_of_a_domain_are_only_in_the_process_of_that_domain() {
    // Only where this test can read another process's memory.
    if zp_sandbox::memory_contains(std::process::id(), b"x").is_none() {
        return;
    }
    common::daemon_is_built();
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("test.zpvault");
    let _stop = StopDaemon(&vault);

    cli(&vault, &["init"], &[PASSWORD, PASSWORD]);
    cli(
        &vault,
        &["add", "login", "--title", "Bank"],
        &[PASSWORD, "bank-password-123"],
    );
    let added = cli(&vault, &["add", "totp"], &[TOTP_URI]);
    let totp_id = added.trim().strip_prefix("added ").unwrap().to_owned();
    // An operation that needs the keys of every domain at once: they meet in
    // a process that is gone afterwards.
    let kit = cli(&vault, &["recovery-kit"], &[PASSWORD]);
    assert!(kit.contains("Recovery key"), "{kit}");
    let code = cli(&vault, &["totp", &totp_id], &[]);
    assert_eq!(code.split_whitespace().next().unwrap().len(), 6, "{code}");

    // Stop the daemon briefly to insert a real passkey credential directly into
    // the vault file (so we know its exact PKCS #8 private key bytes to scan for),
    // then restart and exercise all three domains through the real daemon.
    cli(&vault, &["daemon", "stop"], &[]);
    let dev_key = std::fs::read(vault.with_extension("devkey")).unwrap();
    let store = InsecureSoftwareKeyStore::from_key_bytes(dev_key.as_slice().try_into().unwrap());
    let (password_key, totp_key, passkey_key, passkey_id_hex, passkey_private_key) = {
        let mut opened = Vault::open(&vault).unwrap();
        opened.unlock_password(PASSWORD).unwrap();
        opened.unlock_hardware::<Totp>(&store).unwrap();
        opened.unlock_hardware::<Passkey>(&store).unwrap();
        let created = zp_passkey::create_credential(
            &mut opened,
            &zp_passkey::CreateParams {
                rp_id: "isolation.example".into(),
                rp_name: "Isolation".into(),
                user_handle: b"alice-passkey-handle".to_vec(),
                user_name: "alice@isolation.example".into(),
                user_display_name: "Alice".into(),
                algorithms: vec![zp_passkey::COSE_ALG_ES256],
                exclude_credential_ids: Vec::new(),
            },
        )
        .unwrap();
        let stored: PasskeyCredential = opened.get(created.item_id).unwrap();
        let (_, pk) = opened.export_slot_key::<Password>().unwrap();
        let (_, tk) = opened.export_slot_key::<Totp>().unwrap();
        let (_, kk) = opened.export_slot_key::<Passkey>().unwrap();
        let id_hex: String = created
            .item_id
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        (pk, tk, kk, id_hex, stored.private_key.clone())
    };
    assert!(passkey_private_key.len() >= 32);

    cli(&vault, &["unlock", "password"], &[PASSWORD]);
    cli(&vault, &["unlock", "totp"], &[]);
    cli(&vault, &["unlock", "passkey"], &[]);
    let passkey_view = cli(&vault, &["get", &passkey_id_hex], &[]);
    assert!(passkey_view.contains("isolation.example"), "{passkey_view}");
    let totp_again = cli(&vault, &["totp", &totp_id], &[]);
    assert_eq!(
        totp_again.split_whitespace().next().unwrap().len(),
        6,
        "{totp_again}"
    );
    let status = cli(&vault, &["daemon", "status"], &[]);
    assert!(status.contains("password: unlocked"), "{status}");
    assert!(status.contains("totp:    unlocked"), "{status}");
    assert!(status.contains("passkey: unlocked"), "{status}");

    let front = front_process(&vault);
    let workers = children_of(front);
    assert!(
        workers.len() >= 2,
        "expected both TOTP and passkey workers, got: {workers:?}"
    );

    // The process the clients talk to holds the password domain's key, which
    // shows that this test finds a key where there is one ...
    assert!(
        contains(front, password_key.as_slice()),
        "the password vault key was not found where it must be"
    );
    // ... and nothing of the TOTP or passkey domains: no vault keys, no seed,
    // no passkey private key.
    assert!(
        !contains(front, totp_key.as_slice()),
        "the TOTP vault key is in the memory of the front process"
    );
    assert!(
        !contains(front, TOTP_SEED),
        "a TOTP seed is in the memory of the front process"
    );
    assert!(
        !contains(front, TOTP_SEED_BASE32),
        "the TOTP seed as the client sent it is in the memory of the front process"
    );
    assert!(
        !contains(front, passkey_key.as_slice()),
        "the passkey vault key is in the memory of the front process"
    );
    assert!(
        !contains(front, &passkey_private_key),
        "a passkey private key is in the memory of the front process"
    );

    // The TOTP vault key is in exactly one worker, and the passkey vault key
    // is in exactly one different worker; neither holds VK-P or the other's key.
    let totp_holders: Vec<u32> = workers
        .iter()
        .copied()
        .filter(|&worker| contains(worker, totp_key.as_slice()))
        .collect();
    let passkey_holders: Vec<u32> = workers
        .iter()
        .copied()
        .filter(|&worker| contains(worker, passkey_key.as_slice()))
        .collect();
    assert_eq!(totp_holders.len(), 1, "workers: {workers:?}");
    assert_eq!(passkey_holders.len(), 1, "workers: {workers:?}");
    assert_ne!(
        totp_holders[0], passkey_holders[0],
        "TOTP and passkey keys must not share a worker process"
    );
    assert!(
        !contains(totp_holders[0], &passkey_private_key),
        "a passkey private key is in the TOTP worker"
    );
    for worker in &workers {
        assert!(
            !contains(*worker, password_key.as_slice()),
            "the password vault key is in a worker process"
        );
    }

    // Locked, none of the keys remain in any process.
    cli(&vault, &["lock"], &[]);
    for process in workers.iter().chain([&front]) {
        assert!(
            !contains(*process, totp_key.as_slice()),
            "totp_key in pid {process}"
        );
        assert!(
            !contains(*process, passkey_key.as_slice()),
            "passkey_key in pid {process}"
        );
        assert!(
            !contains(*process, password_key.as_slice()),
            "password_key in pid {process}"
        );
        assert!(
            !contains(*process, &passkey_private_key),
            "passkey_private_key in pid {process} (front={front}, totp={totp_holders:?}, passkey={passkey_holders:?})"
        );
    }
}

/// Stops the daemon when the test ends, also when it fails.
struct StopDaemon<'a>(&'a Path);

impl Drop for StopDaemon<'_> {
    fn drop(&mut self) {
        common::stop_daemon(self.0);
    }
}

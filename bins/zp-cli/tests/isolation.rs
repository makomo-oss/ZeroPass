//! Where the vault keys are (ADR-0007): the acceptance test of the split into
//! one process per key domain. Runs the real daemon, in its sandbox where the
//! platform has one, and reads the memory of its processes the way a program
//! of the same user could.

#![allow(clippy::unwrap_used, reason = "test helpers may panic")]

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use zp_crypto::{InsecureSoftwareKeyStore, Password, Totp};
use zp_vault::Vault;

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
    let status = cli(&vault, &["daemon", "status"], &[]);
    assert!(status.contains("password: unlocked"), "{status}");
    assert!(status.contains("totp:    unlocked"), "{status}");

    // The keys, as this test can work them out from a copy of the vault file
    // and the development key store beside it.
    let copy = dir.path().join("copy.zpvault");
    std::fs::copy(&vault, &copy).unwrap();
    let dev_key = std::fs::read(vault.with_extension("devkey")).unwrap();
    let store = InsecureSoftwareKeyStore::from_key_bytes(dev_key.as_slice().try_into().unwrap());
    let mut opened = Vault::open(&copy).unwrap();
    opened.unlock_password(PASSWORD).unwrap();
    opened.unlock_hardware::<Totp>(&store).unwrap();
    let (_, password_key) = opened.export_slot_key::<Password>().unwrap();
    let (_, totp_key) = opened.export_slot_key::<Totp>().unwrap();
    drop(opened);

    let front = front_process(&vault);
    let workers = children_of(front);
    assert!(!workers.is_empty(), "the daemon has no worker processes");

    // The process the clients talk to holds the password domain's key, which
    // shows that this test finds a key where there is one ...
    assert!(
        contains(front, password_key.as_slice()),
        "the password vault key was not found where it must be"
    );
    // ... and nothing of the TOTP domain: not its vault key, not a seed.
    assert!(
        !contains(front, totp_key.as_slice()),
        "the TOTP vault key is in the memory of the front process"
    );
    assert!(
        !contains(front, TOTP_SEED),
        "a TOTP seed is in the memory of the front process"
    );
    // Not even as the client sent it: the front passed the request on.
    assert!(
        !contains(front, TOTP_SEED_BASE32),
        "the TOTP seed as the client sent it is in the memory of the front process"
    );

    // The TOTP vault key is in exactly one worker, which holds nothing of
    // the password domain.
    let holders: Vec<u32> = workers
        .iter()
        .copied()
        .filter(|&worker| contains(worker, totp_key.as_slice()))
        .collect();
    assert_eq!(holders.len(), 1, "workers: {workers:?}");
    for worker in &workers {
        assert!(
            !contains(*worker, password_key.as_slice()),
            "the password vault key is in a worker process"
        );
    }

    // Locked, it is in none.
    cli(&vault, &["lock"], &[]);
    for process in workers.iter().chain([&front]) {
        assert!(!contains(*process, totp_key.as_slice()));
        assert!(!contains(*process, password_key.as_slice()));
    }
}

/// Stops the daemon when the test ends, also when it fails.
struct StopDaemon<'a>(&'a Path);

impl Drop for StopDaemon<'_> {
    fn drop(&mut self) {
        common::stop_daemon(self.0);
    }
}

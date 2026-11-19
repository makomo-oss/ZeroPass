//! The bridge against the real vault daemon: a vault made with the real
//! `zp-cli`, the real `zp-vaultd` (in its sandbox where there is one), and
//! the real `zp-nmh` spoken to as a browser would.

#![allow(clippy::unwrap_used, reason = "test code may panic")]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Once;

use serde_json::{Value, json};

const PASSWORD: &str = "correct horse battery staple";
const CHROME: &str = "chrome-extension://gehobienihkbhglhnibeobdkgeinamdn/";

fn dir() -> PathBuf {
    Path::new(env!("CARGO_BIN_EXE_zp-nmh"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn program(name: &str) -> PathBuf {
    dir().join(format!("{name}{}", std::env::consts::EXE_SUFFIX))
}

/// `cargo test -p zp-nmh` builds only this package; the daemon and the
/// client that makes the vault are others.
///
/// Once for all the tests of this file, before any of them runs those
/// programs: the tests run in parallel, and Windows cannot replace a program
/// that another test is running ("Access is denied").
fn others_are_built() {
    static BUILT: Once = Once::new();
    BUILT.call_once(|| {
        let mut cargo = Command::new(env!("CARGO"));
        cargo.args([
            "build",
            "--locked",
            "-p",
            "zp-vaultd",
            "-p",
            "zp-cli",
            "-p",
            "zp-keyagent",
        ]);
        if dir().file_name().is_some_and(|name| name == "release") {
            cargo.arg("--release");
        }
        // This build resolves features for three packages, not for the
        // whole workspace, so it may relink programs that `cargo test
        // --workspace` has just built. Windows refuses to replace a program
        // it still holds (a virus scanner, a process that has just ended):
        // "Access is denied (os error 5)". Then the programs already built
        // serve, after a few tries.
        let mut tries = 0;
        loop {
            let output = cargo.output().unwrap();
            if output.status.success() {
                return;
            }
            let stderr = String::from_utf8_lossy(&output.stderr);
            let in_use = stderr.contains("(os error 5)");
            tries += 1;
            if in_use && tries < 4 {
                std::thread::sleep(std::time::Duration::from_secs(2));
                continue;
            }
            let built = ["zp-vaultd", "zp-cli", "zp-keyagent"]
                .iter()
                .all(|name| program(name).exists());
            assert!(in_use && built, "{stderr}");
            eprintln!("note: the other programs are in use; testing the ones already built");
            return;
        }
    });
}

/// Runs `zp-cli` on `vault`; each of `input` answers a prompt.
fn cli(vault: &Path, args: &[&str], input: &[&str]) -> String {
    cli_with(vault, "--no-hardware-keystore", args, input)
}

/// Runs `zp-cli` with the key store `flag`.
fn cli_with(vault: &Path, flag: &str, args: &[&str], input: &[&str]) -> String {
    let mut child = Command::new(program("zp-cli"))
        .arg("--vault")
        .arg(vault)
        .arg(flag)
        .args(args)
        .env_remove("ZEROPASS_VAULT")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    for line in input {
        writeln!(stdin, "{line}").unwrap();
    }
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "zp-cli {args:?}: {stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    stdout
}

fn added(stdout: &str) -> String {
    stdout
        .lines()
        .find_map(|line| line.strip_prefix("added "))
        .unwrap()
        .trim()
        .to_owned()
}

/// The bridge, started as a browser starts it.
struct Bridge {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
    next: u64,
}

impl Bridge {
    fn start(vault: &Path, args: &[&str]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_zp-nmh"))
            .args(args)
            .env("ZEROPASS_VAULT", vault)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        Self {
            child,
            stdin,
            stdout,
            next: 1,
        }
    }

    fn ask(&mut self, mut request: Value) -> Value {
        let id = self.next;
        self.next += 1;
        request["id"] = json!(id);
        let body = serde_json::to_vec(&request).unwrap();
        self.stdin
            .write_all(&u32::try_from(body.len()).unwrap().to_ne_bytes())
            .unwrap();
        self.stdin.write_all(&body).unwrap();
        self.stdin.flush().unwrap();
        let mut length = [0u8; 4];
        self.stdout.read_exact(&mut length).unwrap();
        let mut reply = vec![0u8; u32::from_ne_bytes(length) as usize];
        self.stdout.read_exact(&mut reply).unwrap();
        let reply: Value = serde_json::from_slice(&reply).unwrap();
        assert_eq!(reply["id"], json!(id));
        reply
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn error_code(reply: &Value) -> &str {
    assert_eq!(reply["ok"], json!(false), "{reply}");
    reply["error"]["code"].as_str().unwrap()
}

/// Stops the vault's daemon when the test ends, whatever happens.
struct Daemon<'a>(&'a Path);

impl Drop for Daemon<'_> {
    fn drop(&mut self) {
        let _ = Command::new(program("zp-cli"))
            .arg("--vault")
            .arg(self.0)
            .args(["daemon", "stop"])
            .env_remove("ZEROPASS_VAULT")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

#[test]
fn the_extension_gets_only_the_logins_of_the_page() {
    others_are_built();
    let temp = tempfile::tempdir().unwrap();
    let vault = temp.path().join("bridge.zpvault");
    let _daemon = Daemon(&vault);

    // No vault yet.
    let mut bridge = Bridge::start(&vault, &[CHROME]);
    let status = bridge.ask(json!({ "type": "status" }));
    assert_eq!(status["vault"], json!(false), "{status}");

    cli(&vault, &["init"], &[PASSWORD, PASSWORD]);
    let bank = added(&cli(
        &vault,
        &[
            "add",
            "login",
            "--title",
            "Bank",
            "--username",
            "alice",
            "--url",
            "https://bank.example.com/login",
        ],
        &[PASSWORD, "bank password"],
    ));
    let mail = added(&cli(
        &vault,
        &[
            "add",
            "login",
            "--title",
            "Mail",
            "--username",
            "alice@mail.test",
            "--url",
            "mail.example.org",
        ],
        &["mail password"],
    ));
    cli(&vault, &["lock"], &[]);

    // Locked: the bridge cannot unlock; the user is sent to the application.
    let status = bridge.ask(json!({ "type": "status" }));
    assert_eq!(
        (&status["vault"], &status["running"], &status["unlocked"]),
        (&json!(true), &json!(true), &json!(false)),
        "{status}"
    );
    let locked = bridge.ask(json!({ "type": "find", "origin": "https://bank.example.com" }));
    assert_eq!(error_code(&locked), "Locked", "{locked}");

    cli(&vault, &["unlock"], &[PASSWORD]);

    // The page's own login, exactly; another host of the same site.
    let found = bridge.ask(json!({ "type": "find", "origin": "https://bank.example.com" }));
    let logins = found["logins"].as_array().unwrap();
    assert_eq!(logins.len(), 1, "{found}");
    assert_eq!(logins[0]["id"], json!(bank));
    assert_eq!(logins[0]["match"], json!("exact"));
    assert!(logins[0].get("password").is_none(), "{found}");
    let site = bridge.ask(json!({ "type": "find", "origin": "https://secure.example.com" }));
    assert_eq!(site["logins"][0]["match"], json!("site"), "{site}");

    // Nothing for another site, a look-alike, or a downgrade to http.
    for origin in [
        "https://evil.test",
        "https://bank.example.com.evil.test",
        "http://bank.example.com",
    ] {
        let none = bridge.ask(json!({ "type": "find", "origin": origin }));
        assert_eq!(none["logins"], json!([]), "{origin}: {none}");
    }

    // The password of the page's login, and only for its page.
    let filled =
        bridge.ask(json!({ "type": "fill", "origin": "https://bank.example.com", "item": bank }));
    assert_eq!(filled["username"], json!("alice"), "{filled}");
    assert_eq!(filled["password"], json!("bank password"));
    let refused =
        bridge.ask(json!({ "type": "fill", "origin": "https://bank.example.com", "item": mail }));
    assert_eq!(error_code(&refused), "Denied");
    let malformed = bridge.ask(json!({ "type": "find", "origin": "bank.example.com" }));
    assert_eq!(error_code(&malformed), "BadRequest");
    let unknown = bridge.ask(json!({ "type": "list" }));
    assert_eq!(error_code(&unknown), "BadRequest");
    drop(bridge);

    // A daemon that is not running is not started by the bridge.
    cli(&vault, &["daemon", "stop"], &[]);
    let mut bridge = Bridge::start(&vault, &[CHROME]);
    let status = bridge.ask(json!({ "type": "status" }));
    assert_eq!(status["running"], json!(false), "{status}");
    let stopped = bridge.ask(json!({ "type": "find", "origin": "https://bank.example.com" }));
    assert_eq!(error_code(&stopped), "NotRunning");
}

#[test]
fn another_extension_is_not_served() {
    let temp = tempfile::tempdir().unwrap();
    let vault = temp.path().join("none.zpvault");
    for args in [
        &["chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"][..],
        &["manifest.json", "someone@example.com"][..],
        &[][..],
    ] {
        let mut bridge = Bridge::start(&vault, args);
        // It ends without reading or answering.
        let status = bridge.child.wait().unwrap();
        assert!(status.success());
        let mut rest = Vec::new();
        bridge.stdout.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty(), "{args:?}");
    }
}

#[test]
fn the_extension_saves_compares_updates_and_gets_one_time_codes() {
    others_are_built();
    let temp = tempfile::tempdir().unwrap();
    let vault = temp.path().join("totp.zpvault");
    let _daemon = Daemon(&vault);
    // The development key store stands in for Windows Hello.
    let soft = "--insecure-software-keystore";
    cli_with(&vault, soft, &["init"], &[PASSWORD, PASSWORD]);
    let bank = added(&cli_with(
        &vault,
        soft,
        &[
            "add",
            "login",
            "--title",
            "Bank",
            "--username",
            "alice",
            "--url",
            "https://bank.example.com",
        ],
        &[PASSWORD, "bank password"],
    ));
    cli_with(
        &vault,
        soft,
        &["add", "totp", "--login", &bank],
        &["otpauth://totp/Bank:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"],
    );
    let origin = "https://bank.example.com";
    let mut bridge = Bridge::start(&vault, &[CHROME]);

    let code = bridge.ask(json!({ "type": "totp", "origin": origin, "item": bank }));
    let digits = code["code"].as_str().unwrap_or_default();
    assert!(
        digits.len() == 6 && digits.chars().all(|c| c.is_ascii_digit()),
        "{code}"
    );
    let elsewhere =
        bridge.ask(json!({ "type": "totp", "origin": "https://evil.test", "item": bank }));
    assert_eq!(error_code(&elsewhere), "Denied");

    let compare = |bridge: &mut Bridge, username: &str, password: &str| {
        bridge.ask(json!({
            "type": "compare", "origin": origin, "username": username, "password": password
        }))
    };
    let same = compare(&mut bridge, "alice", "bank password");
    assert_eq!(
        (&same["item"], &same["same"]),
        (&json!(bank), &json!(true)),
        "{same}"
    );
    let changed = compare(&mut bridge, "alice", "new bank password");
    assert_eq!(changed["same"], json!(false), "{changed}");
    let updated = bridge.ask(json!({
        "type": "update", "origin": origin, "item": bank, "password": "new bank password"
    }));
    assert_eq!(updated["ok"], json!(true), "{updated}");
    assert_eq!(
        compare(&mut bridge, "alice", "new bank password")["same"],
        json!(true)
    );

    let fresh = compare(&mut bridge, "carol", "carol password");
    assert_eq!(fresh["item"], json!(""), "{fresh}");
    let saved = bridge.ask(json!({
        "type": "save", "origin": origin, "username": "carol", "password": "carol password"
    }));
    let id = saved["item"].as_str().unwrap().to_owned();
    let found = bridge.ask(json!({ "type": "find", "origin": origin }));
    assert!(
        found["logins"]
            .as_array()
            .unwrap()
            .iter()
            .any(|login| login["id"] == json!(id)),
        "{found}"
    );
}

#[test]
fn the_extension_creates_lists_and_signs_passkeys() {
    others_are_built();
    let temp = tempfile::tempdir().unwrap();
    let vault = temp.path().join("passkey.zpvault");
    let _daemon = Daemon(&vault);
    let soft = "--insecure-software-keystore";
    cli_with(&vault, soft, &["init"], &[PASSWORD, PASSWORD]);

    let origin = "https://webauthn.io";
    let hash_32 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 32 zero bytes in base64url
    let mut bridge = Bridge::start(&vault, &[CHROME]);

    let status = bridge.ask(json!({ "type": "status" }));
    assert_eq!(status["passkey"], json!(true), "{status}");

    // Create first passkey (alice).
    let created = bridge.ask(json!({
        "type": "passkey_create",
        "origin": origin,
        "rp_id": "webauthn.io",
        "rp_name": "webauthn.io",
        "user_handle": "YWxpY2U",
        "user_name": "alice",
        "user_display_name": "Alice",
        "algorithms": [-7, -8],
        "exclude_credential_ids": [],
        "client_data_hash": hash_32
    }));
    assert_eq!(created["ok"], json!(true), "{created}");
    assert_eq!(created["cose_algorithm"], json!(-7));
    let cred_id = created["credential_id"].as_str().unwrap().to_owned();
    assert!(!created["attestation_object"].as_str().unwrap().is_empty());
    assert!(!created["authenticator_data"].as_str().unwrap().is_empty());
    assert!(!created["public_key_spki"].as_str().unwrap().is_empty());

    // List matches on the same origin.
    let listed = bridge.ask(json!({
        "type": "passkey_list",
        "origin": origin,
        "rp_id": "webauthn.io"
    }));
    assert_eq!(
        listed["candidates"].as_array().unwrap().len(),
        1,
        "{listed}"
    );
    assert_eq!(listed["candidates"][0]["credential_id"], json!(cred_id));

    // Excluded credential ID is rejected with CredentialExcluded.
    let excluded = bridge.ask(json!({
        "type": "passkey_create",
        "origin": origin,
        "rp_id": "webauthn.io",
        "rp_name": "webauthn.io",
        "user_handle": "Ym9i",
        "user_name": "bob",
        "user_display_name": "Bob",
        "algorithms": [-7],
        "exclude_credential_ids": [cred_id],
        "client_data_hash": hash_32
    }));
    assert_eq!(error_code(&excluded), "CredentialExcluded", "{excluded}");

    // Single-credential assertion signs directly.
    let assertion = bridge.ask(json!({
        "type": "passkey_get",
        "origin": origin,
        "rp_id": "webauthn.io",
        "client_data_hash": hash_32
    }));
    assert_eq!(assertion["ok"], json!(true), "{assertion}");
    assert_eq!(assertion["credential_id"], json!(cred_id));
    assert_eq!(assertion["user_handle"], json!("YWxpY2U"));
    assert!(!assertion["signature"].as_str().unwrap().is_empty());

    // Add a second passkey (bob); get without credential_id returns both candidates.
    let created_bob = bridge.ask(json!({
        "type": "passkey_create",
        "origin": origin,
        "rp_id": "webauthn.io",
        "rp_name": "webauthn.io",
        "user_handle": "Ym9i",
        "user_name": "bob",
        "user_display_name": "Bob",
        "algorithms": [-8],
        "exclude_credential_ids": [],
        "client_data_hash": hash_32
    }));
    assert_eq!(created_bob["cose_algorithm"], json!(-8), "{created_bob}");
    let bob_cred_id = created_bob["credential_id"].as_str().unwrap().to_owned();

    let multi = bridge.ask(json!({
        "type": "passkey_get",
        "origin": origin,
        "rp_id": "webauthn.io",
        "client_data_hash": hash_32
    }));
    assert_eq!(multi["candidates"].as_array().unwrap().len(), 2, "{multi}");

    // Selecting bob signs with bob's credential.
    let bob_assert = bridge.ask(json!({
        "type": "passkey_get",
        "origin": origin,
        "rp_id": "webauthn.io",
        "client_data_hash": hash_32,
        "credential_id": bob_cred_id
    }));
    assert_eq!(bob_assert["ok"], json!(true), "{bob_assert}");
    assert_eq!(bob_assert["credential_id"], json!(bob_cred_id));
    assert_eq!(bob_assert["user_handle"], json!("Ym9i"));

    // Cross-origin RP ID is denied.
    let evil = bridge.ask(json!({
        "type": "passkey_get",
        "origin": "https://evil.test",
        "rp_id": "webauthn.io",
        "client_data_hash": hash_32
    }));
    assert_eq!(error_code(&evil), "Denied", "{evil}");
}

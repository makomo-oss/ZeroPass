//! A passkey made on one device signs on another after a sync (task P5-05):
//! two vaults paired on the local network, the passkey made through the
//! first one's browser bridge (`zp-nmh`), synced, and used through the
//! second one's bridge. The relying party checks the signature with the
//! public key it got at registration. Everything is the real programs; the
//! development key store stands in for Windows Hello.
//!
//! Needs a network interface with a private address and working multicast:
//!
//! ```text
//! cargo test -p zp-cli --test passkey_sync -- --ignored
//! ```

#![allow(clippy::unwrap_used, reason = "test code may panic")]

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{Value, json};

mod common;

const PC_PASSWORD: &str = "correct horse battery staple";
const PHONE_PASSWORD: &str = "an entirely different passphrase";
const CHROME: &str = "chrome-extension://gehobienihkbhglhnibeobdkgeinamdn/";
const ORIGIN: &str = "https://login.example.com";

fn program(name: &str) -> PathBuf {
    Path::new(env!("CARGO_BIN_EXE_zp-cli"))
        .with_file_name(format!("{name}{}", std::env::consts::EXE_SUFFIX))
}

/// The bridge is another package: `cargo test -p zp-cli` does not build it.
fn bridge_is_built() {
    let mut cargo = Command::new(env!("CARGO"));
    cargo.args(["build", "--locked", "-p", "zp-nmh"]);
    if program("zp-cli")
        .parent()
        .and_then(Path::file_name)
        .is_some_and(|name| name == "release")
    {
        cargo.arg("--release");
    }
    let output = cargo.output().unwrap();
    assert!(
        output.status.success(),
        "building the bridge failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// One device: a vault file and its daemons, stopped at the end.
struct Device {
    _dir: tempfile::TempDir,
    vault: PathBuf,
}

impl Device {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        Self {
            vault: dir.path().join("vault.zpvault"),
            _dir: dir,
        }
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_zp-cli"));
        command
            .arg("--vault")
            .arg(&self.vault)
            .arg("--insecure-software-keystore")
            .args(args)
            .env_remove("ZEROPASS_VAULT");
        command
    }

    fn ok(&self, args: &[&str], input: &[&str]) -> String {
        let mut child = self
            .command(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        for line in input {
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
}

impl Drop for Device {
    fn drop(&mut self) {
        common::stop_daemon(&self.vault);
    }
}

/// The browser bridge of a device, spoken to as a browser would.
struct Bridge {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
    next: u64,
}

impl Bridge {
    fn start(device: &Device) -> Self {
        let mut child = Command::new(program("zp-nmh"))
            .arg(CHROME)
            .env("ZEROPASS_VAULT", &device.vault)
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
        request["id"] = json!(self.next);
        self.next += 1;
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
        assert_eq!(reply["ok"], json!(true), "{reply}");
        reply
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Reads the bridge's base64url.
fn bytes(reply: &Value, name: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let text = reply[name]
        .as_str()
        .unwrap_or_else(|| panic!("no {name}: {reply}"));
    let (mut bits, mut count, mut out) = (0u32, 0, Vec::new());
    for symbol in text.bytes() {
        let value = ALPHABET.iter().position(|&c| c == symbol).unwrap();
        bits = bits << 6 | u32::try_from(value).unwrap();
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push(u8::try_from(bits >> count & 0xff).unwrap());
        }
    }
    out
}

/// Pairs `phone` to `pc` with a pairing code, over the local network.
fn pair(pc: &Device, phone: &Device) {
    pc.ok(&["lock"], &[]);
    let mut pairing = pc
        .command(&["pair"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = pairing.stdin.take().unwrap();
    writeln!(stdin, "{PC_PASSWORD}").unwrap();
    writeln!(stdin, "y").unwrap();
    let mut stdout = BufReader::new(pairing.stdout.take().unwrap());
    let code = loop {
        let mut line = String::new();
        assert!(stdout.read_line(&mut line).unwrap() > 0, "no pairing code");
        if line.starts_with("ZP1:") {
            break line.trim().to_owned();
        }
    };
    let joined = phone.ok(
        &["join", "--name", "Second device"],
        &[PHONE_PASSWORD, PHONE_PASSWORD, &code],
    );
    assert!(joined.contains("joined vault"), "{joined}");
    assert!(joined.contains("passkey: available"), "{joined}");
    let mut rest = String::new();
    stdout.read_to_string(&mut rest).unwrap();
    assert!(pairing.wait().unwrap().success(), "{rest}");
    drop(stdin);
}

/// Syncs both devices with each other, at the same time.
fn sync(pc: &Device, phone: &Device) {
    let pc_sync = pc
        .command(&["sync", "--seconds", "15"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let phone_out = phone.ok(&["sync", "--seconds", "15"], &[]);
    let pc_out = String::from_utf8(pc_sync.wait_with_output().unwrap().stdout).unwrap();
    assert!(
        phone_out.contains("synced with \"") && pc_out.contains("synced with \""),
        "{phone_out}\n{pc_out}"
    );
}

#[test]
#[ignore = "needs a local network interface with multicast"]
fn a_passkey_made_on_one_device_signs_on_the_other() {
    common::daemon_is_built();
    bridge_is_built();
    let pc = Device::new();
    let phone = Device::new();
    pc.ok(&["init"], &[PC_PASSWORD, PC_PASSWORD]);
    pair(&pc, &phone);

    // The relying party registers a passkey through the PC's browser.
    let created = Bridge::start(&pc).ask(json!({
        "type": "passkey_create", "origin": ORIGIN, "rp_id": "example.com", "rp_name": "Example",
        "user_id": "YWxpY2U", "user_name": "alice", "user_display_name": "Alice",
        "challenge": "cmVnaXN0cmF0aW9uLWNoYWxsZW5nZQ", "algorithms": [-7]
    }));
    let public_key = bytes(&created, "public_key");
    // Two devices hold the vault: the passkey is backed up (BS).
    let data = bytes(&created, "authenticator_data");
    assert_eq!(data[32] & 0x18, 0x18, "flags {:#04x}", data[32]);

    sync(&pc, &phone);

    // The second device signs with it, through its own browser bridge, and
    // the relying party accepts the signature.
    let signed = Bridge::start(&phone).ask(json!({
        "type": "passkey_get", "origin": ORIGIN, "rp_id": "example.com",
        "challenge": "c2lnbi1pbi1vbi10aGUtc2Vjb25kLWRldmljZQ"
    }));
    assert_eq!(signed["credential_id"], created["credential_id"]);
    assert_eq!(bytes(&signed, "user_handle"), b"alice");
    let client_data = String::from_utf8(bytes(&signed, "client_data_json")).unwrap();
    assert!(
        client_data.contains(r#""origin":"https://login.example.com""#),
        "{client_data}"
    );
    assert!(zp_passkey::authenticator::verify(
        &public_key,
        &bytes(&signed, "authenticator_data"),
        &bytes(&signed, "client_data_json"),
        &bytes(&signed, "signature"),
    ));

    // A passkey deleted on the second device is gone from the first after
    // the next sync.
    let listed = phone.ok(&["list", "--domain", "passkey"], &[PHONE_PASSWORD]);
    let item = listed
        .lines()
        .find(|line| line.contains("example.com"))
        .and_then(|line| line.split_whitespace().next())
        .unwrap_or_else(|| panic!("not listed: {listed}"))
        .to_owned();
    phone.ok(&["delete", &item], &[PHONE_PASSWORD]);
    sync(&pc, &phone);
    let listed = pc.ok(&["list", "--domain", "passkey"], &[PC_PASSWORD]);
    assert!(listed.contains("0 item(s)"), "{listed}");
}

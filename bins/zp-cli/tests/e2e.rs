//! End-to-end test of the command-line client: runs the real binary against a
//! vault file in a temporary directory, feeding prompts through standard input.
//! The client starts the real vault daemon, one per vault file; what a command
//! unlocks stays unlocked there until `lock`.

#![allow(clippy::unwrap_used, reason = "test helpers may panic")]

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

mod common;

const PASSWORD: &str = "correct horse battery staple";
const NEW_PASSWORD: &str = "an entirely different passphrase";
/// The RFC 6238 SHA-1 test secret.
const TOTP_URI: &str =
    "otpauth://totp/Example:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example";

struct Output {
    success: bool,
    stdout: String,
    stderr: String,
}

struct Cli {
    _dir: tempfile::TempDir,
    vault: PathBuf,
}

impl Cli {
    fn new() -> Self {
        common::daemon_is_built();
        let dir = tempfile::tempdir().unwrap();
        Self {
            vault: dir.path().join("test.zpvault"),
            _dir: dir,
        }
    }

    /// Runs `zp-cli` with `args`; each element of `input` answers one prompt.
    fn run_with(&self, software_keystore: bool, args: &[&str], input: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_zp-cli"));
        command.arg("--vault").arg(&self.vault);
        // Never touch the real platform key store (Windows Hello would prompt).
        command.arg(if software_keystore {
            "--insecure-software-keystore"
        } else {
            "--no-hardware-keystore"
        });
        let mut child = command
            .args(args)
            .env_remove("ZEROPASS_VAULT")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        for line in input {
            // The CLI may exit before it has read every answer, for example
            // when it refuses the command outright.
            if let Err(error) = writeln!(stdin, "{line}") {
                assert_eq!(error.kind(), io::ErrorKind::BrokenPipe, "{error}");
                break;
            }
        }
        drop(stdin);
        let output = child.wait_with_output().unwrap();
        Output {
            success: output.status.success(),
            stdout: String::from_utf8(output.stdout).unwrap(),
            stderr: String::from_utf8(output.stderr).unwrap(),
        }
    }

    fn run(&self, args: &[&str], input: &[&str]) -> Output {
        self.run_with(true, args, input)
    }

    fn ok(&self, args: &[&str], input: &[&str]) -> String {
        let output = self.run(args, input);
        assert!(output.success, "{args:?} failed: {}", output.stderr);
        output.stdout
    }

    fn fails(&self, args: &[&str], input: &[&str]) -> String {
        let output = self.run(args, input);
        assert!(
            !output.success,
            "{args:?} unexpectedly succeeded: {}",
            output.stdout
        );
        output.stderr
    }
}

impl Drop for Cli {
    fn drop(&mut self) {
        common::stop_daemon(&self.vault);
    }
}

fn added_id(stdout: &str) -> String {
    let id = stdout
        .trim()
        .strip_prefix("added ")
        .expect("`added <id>`")
        .to_owned();
    assert_eq!(id.len(), 32);
    id
}

/// Extracts the recovery key from the output of `recovery-kit`.
fn recovery_code(stdout: &str) -> String {
    stdout
        .lines()
        .map(str::trim)
        .find(|line| line.len() == 65 && line.matches('-').count() == 10)
        .unwrap_or_else(|| panic!("no recovery key in: {stdout}"))
        .to_owned()
}

fn file_contains(path: &Path, needle: &str) -> bool {
    let bytes = std::fs::read(path).unwrap();
    bytes
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

#[test]
fn init_add_get_list_totp_and_lock() {
    let cli = Cli::new();

    // init
    let out = cli.ok(&["init"], &[PASSWORD, PASSWORD]);
    assert!(out.contains("created vault"), "{out}");
    assert!(out.contains("totp:    available"), "{out}");
    assert!(cli.vault.exists());
    let stderr = cli.fails(&["init"], &[PASSWORD, PASSWORD]);
    assert!(stderr.contains("already exists"), "{stderr}");

    // devices: readable without unlocking anything
    let out = cli.ok(&["devices"], &[]);
    assert!(out.contains("this device"), "{out}");
    assert!(out.contains("0 change(s) held"), "{out}");
    assert!(out.contains("1 device(s)"), "{out}");
    // revoke: only other devices, named by (the start of) their identifier
    let own_id = out.split_whitespace().next().unwrap().to_owned();
    let stderr = cli.fails(&["revoke", &own_id], &[]);
    assert!(stderr.contains("cannot revoke itself"), "{stderr}");
    let stderr = cli.fails(&["revoke", "not-an-identifier"], &[]);
    assert!(stderr.contains("no device has that identifier"), "{stderr}");

    // add: the master password is prompted first, then the item's secret
    let login_id = added_id(&cli.ok(
        &[
            "add",
            "login",
            "--title",
            "Example Bank",
            "--username",
            "alice",
            "--url",
            "https://bank.example",
        ],
        &[PASSWORD, "s3cret-login-password"],
    ));
    // The password domain is still unlocked: only the note text is asked for.
    let note_id = added_id(&cli.ok(
        &["add", "note", "--title", "Wi-Fi"],
        &["the wifi passphrase"],
    ));
    let totp_id = added_id(&cli.ok(&["add", "totp", "--login", &login_id], &[TOTP_URI]));

    // Nothing the user typed is stored in the clear.
    for secret in [
        "s3cret-login-password",
        "the wifi passphrase",
        "Example Bank",
        "GEZDGNBV",
        "alice",
    ] {
        assert!(
            !file_contains(&cli.vault, secret),
            "{secret:?} is readable in the vault file"
        );
    }

    // The daemon keeps a domain unlocked between commands, until it is locked.
    assert!(cli.ok(&["list"], &[]).contains("2 item(s)"));
    let out = cli.ok(&["daemon", "status"], &[]);
    assert!(out.contains("password: unlocked"), "{out}");
    assert!(out.contains("totp:    unlocked"), "{out}");
    assert!(out.contains("passkey: locked"), "{out}");
    // Where the platform has a sandbox, the daemon was started inside it.
    if cfg!(windows) {
        assert!(out.contains("sandbox: yes"), "{out}");
    }
    assert!(cli.ok(&["lock"], &[]).contains("locked: all domains"));
    let stderr = cli.fails(&["list"], &[]);
    assert!(stderr.contains("unexpected end of input"), "{stderr}");

    // list
    let out = cli.ok(&["list"], &[PASSWORD]);
    assert!(
        out.contains(&format!("{login_id}  Login       Example Bank")),
        "{out}"
    );
    assert!(
        out.contains(&format!("{note_id}  SecureNote  Wi-Fi")),
        "{out}"
    );
    assert!(out.contains("2 item(s)"), "{out}");
    assert!(
        !out.contains(&totp_id),
        "TOTP entries are not in the password domain"
    );
    let out = cli.ok(&["list", "--domain", "totp"], &[]);
    assert!(
        out.contains(&format!("{totp_id}  Totp        Example")),
        "{out}"
    );

    // get: secrets are masked unless asked for
    let out = cli.ok(&["get", &login_id], &[PASSWORD]);
    assert!(out.contains("title:    Example Bank"), "{out}");
    assert!(out.contains("username: alice"), "{out}");
    assert!(out.contains("url:      https://bank.example"), "{out}");
    assert!(!out.contains("s3cret-login-password"), "{out}");
    let out = cli.ok(&["get", &login_id, "--reveal"], &[PASSWORD]);
    assert!(out.contains("password: s3cret-login-password"), "{out}");
    let out = cli.ok(&["get", &totp_id], &[]);
    assert!(out.contains(&format!("login:   {login_id}")), "{out}");
    assert!(
        !out.contains("GEZDGNBV"),
        "the seed is never printed: {out}"
    );

    // get --copy: the password goes to the clipboard, not to the terminal.
    // This replaces what is on the clipboard, so it runs only when asked to
    // (ZEROPASS_TEST_CLIPBOARD=1); the text that was there is put back.
    if cfg!(windows) && std::env::var_os("ZEROPASS_TEST_CLIPBOARD").is_some() {
        let before = zp_clipboard::text().unwrap();
        let out = cli.ok(&["get", &login_id, "--copy"], &[]);
        assert!(out.contains("password copied to the clipboard"), "{out}");
        assert!(!out.contains("s3cret-login-password"), "{out}");
        assert_eq!(
            zp_clipboard::text().unwrap().as_deref(),
            Some("s3cret-login-password")
        );
        let out = cli.ok(&["totp", &totp_id, "--copy"], &[]);
        assert!(out.contains("code copied to the clipboard"), "{out}");
        let code = zp_clipboard::text().unwrap().unwrap();
        assert!(code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()));
        let stderr = cli.fails(&["get", &totp_id, "--copy"], &[]);
        assert!(stderr.contains("can be copied"), "{stderr}");

        // The helper that the copy left behind clears the clipboard when its
        // time is up (here: at once), unless something else was copied since.
        let copied = zp_clipboard::copy_secret("still the secret").unwrap();
        let token = copied.token().to_string();
        cli.ok(&["clipboard-clear", "--after", "0", "--token", &token], &[]);
        assert_eq!(zp_clipboard::text().unwrap(), None);
        let copied = zp_clipboard::copy_secret("the secret").unwrap();
        let token = copied.token().to_string();
        zp_clipboard::set_text("copied by the user since").unwrap();
        cli.ok(&["clipboard-clear", "--after", "0", "--token", &token], &[]);
        assert_eq!(
            zp_clipboard::text().unwrap().as_deref(),
            Some("copied by the user since")
        );
        if let Some(text) = before {
            zp_clipboard::set_text(&text).unwrap();
        }
    }

    // totp
    let out = cli.ok(&["totp", &totp_id], &[]);
    let code = out.split_whitespace().next().unwrap();
    assert!(
        code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()),
        "{out}"
    );
    assert!(out.contains("(valid for "), "{out}");

    // wrong master password and unknown items
    cli.ok(&["lock"], &[]);
    let stderr = cli.fails(&["list"], &["not the master password"]);
    assert!(stderr.contains("wrong master password"), "{stderr}");
    let stderr = cli.fails(&["get", &"0".repeat(32)], &[PASSWORD]);
    assert!(stderr.contains("does not exist"), "{stderr}");

    // unlock / lock inside one shell session
    cli.ok(&["lock"], &[]);
    let script = [
        "list", // locked: prompts for the master password
        PASSWORD,
        "list", // still unlocked: no prompt
        "lock",
        "list", // locked again: prompts
        "definitely not the password",
        "unlock",
        PASSWORD,
        &format!("get {note_id} --reveal"),
        "unlock totp",
        &format!("totp {totp_id}"),
        "lock totp",
        "add note --title \"Second note\"",
        "body of the second note",
        "exit",
    ];
    let out = cli.ok(&["shell"], &script);
    assert_eq!(out.matches("2 item(s)").count(), 2, "{out}");
    assert!(out.contains("locked: all domains"), "{out}");
    assert!(out.contains("error: wrong master password"), "{out}");
    assert!(out.contains("unlocked: password"), "{out}");
    assert!(out.contains("text:  the wifi passphrase"), "{out}");
    assert!(out.contains("unlocked: totp"), "{out}");
    assert!(out.contains("locked: totp"), "{out}");
    assert!(out.contains("added "), "{out}");
    // Leaving the shell locks everything.
    let out = cli.ok(&["daemon", "status"], &[]);
    assert!(out.contains("password: locked"), "{out}");

    // delete
    let out = cli.ok(&["delete", &note_id], &[PASSWORD]);
    assert!(out.contains(&format!("deleted {note_id}")), "{out}");
    assert!(cli.ok(&["list"], &[PASSWORD]).contains("2 item(s)"));

    // passwd
    let stderr = cli.fails(
        &["passwd"],
        &[PASSWORD, NEW_PASSWORD, "a typo in the repetition"],
    );
    assert!(stderr.contains("do not match"), "{stderr}");
    cli.ok(&["passwd"], &[PASSWORD, NEW_PASSWORD, NEW_PASSWORD]);
    // Changing the password locks what the old one had unlocked.
    cli.fails(&["list"], &[PASSWORD]);
    assert!(cli.ok(&["list"], &[NEW_PASSWORD]).contains("2 item(s)"));

    // Stopping the daemon locks everything; the next command starts it again.
    let out = cli.ok(&["daemon", "stop"], &[]);
    assert!(out.contains("was stopped"), "{out}");
    let out = cli.ok(&["daemon", "status"], &[]);
    assert!(out.contains("not running"), "{out}");
    cli.fails(&["list"], &[]);
    assert!(cli.ok(&["list"], &[NEW_PASSWORD]).contains("2 item(s)"));
    let out = cli.ok(&["daemon", "status"], &[]);
    assert!(out.contains("is running"), "{out}");

    // For development, the daemon can be started outside the sandbox.
    cli.ok(&["daemon", "stop"], &[]);
    let out = cli.ok(&["--no-sandbox", "daemon", "start"], &[]);
    assert!(out.contains("sandbox: NO"), "{out}");
    assert!(cli.ok(&["list"], &[NEW_PASSWORD]).contains("2 item(s)"));
}

#[test]
fn without_a_hardware_key_store_the_totp_domain_is_unavailable() {
    let cli = Cli::new();
    let output = cli.run_with(false, &["init"], &[PASSWORD, PASSWORD]);
    assert!(output.success, "{}", output.stderr);
    assert!(
        output.stdout.contains("totp:    not available"),
        "{}",
        output.stdout
    );

    let output = cli.run_with(false, &["add", "totp"], &[TOTP_URI]);
    assert!(!output.success);
    assert!(
        output.stderr.contains("no totp domain"),
        "{}",
        output.stderr
    );

    // The password domain works as usual.
    let output = cli.run_with(false, &["add", "login", "--title", "x"], &[PASSWORD, "pw"]);
    assert!(output.success, "{}", output.stderr);
}

#[test]
fn bad_invocations_fail_cleanly() {
    let cli = Cli::new();
    let stderr = cli.fails(&["list"], &[PASSWORD]);
    assert!(stderr.contains("no vault file exists"), "{stderr}");
    let stderr = cli.fails(&["init"], &["short", "short"]);
    assert!(stderr.contains("at least 12 characters"), "{stderr}");
    assert!(!cli.vault.exists());
    assert!(!cli.vault.with_extension("devkey").exists());
    let stderr = cli.fails(&["init"], &[PASSWORD, "something else entirely"]);
    assert!(stderr.contains("do not match"), "{stderr}");

    // Without a vault named, the user's own vault is meant (ADR-0008). Here
    // the user's directories are a temporary one, and it holds no vault yet.
    let home = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_zp-cli"))
        .arg("list")
        .env_remove("ZEROPASS_VAULT")
        .env("LOCALAPPDATA", home.path())
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", home.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no vault file exists"), "{stderr}");
    let default_directory = if cfg!(windows) {
        home.path().join("ZeroPass").join("Vault")
    } else if cfg!(target_os = "macos") {
        home.path()
            .join("Library/Application Support/ZeroPass/Vault")
    } else {
        home.path().join("zeropass").join("Vault")
    };
    // Its directory is there, ready for `init`.
    assert!(
        default_directory.is_dir(),
        "{}",
        default_directory.display()
    );
}

#[test]
fn recovery_kit_restores_the_vault_in_a_new_location() {
    let cli = Cli::new();
    cli.ok(&["init"], &[PASSWORD, PASSWORD]);
    let login_id = added_id(&cli.ok(
        &["add", "login", "--title", "Bank"],
        &[PASSWORD, "login-password"],
    ));
    let totp_id = added_id(&cli.ok(&["add", "totp"], &[TOTP_URI]));

    // Create the kit: the master password unlocks the password domain, the key
    // store the other two.
    let out = cli.ok(&["recovery-kit"], &[PASSWORD]);
    let code = recovery_code(&out);
    assert!(!file_contains(&cli.vault, &code));
    // A second kit needs an explicit --replace.
    let stderr = cli.fails(&["recovery-kit"], &[PASSWORD]);
    assert!(stderr.contains("--replace"), "{stderr}");

    // A new device: only the backup of the vault file and the paper survive.
    let restored = Cli::new();
    std::fs::copy(&cli.vault, &restored.vault).unwrap();
    assert!(!restored.vault.with_extension("devkey").exists());

    let stderr = restored.fails(
        &["recover"],
        &["not a recovery key", NEW_PASSWORD, NEW_PASSWORD],
    );
    assert!(stderr.contains("recovery key is not valid"), "{stderr}");
    // A well-formed key that belongs to a different vault.
    let other = Cli::new();
    assert!(
        other
            .run_with(false, &["init"], &[PASSWORD, PASSWORD])
            .success
    );
    let other_out = other.run_with(false, &["recovery-kit"], &[PASSWORD]).stdout;
    let other_key = recovery_code(&other_out);
    let stderr = restored.fails(&["recover"], &[&other_key, NEW_PASSWORD, NEW_PASSWORD]);
    assert!(stderr.contains("does not match this vault"), "{stderr}");

    // Typed in lower case with spaces, as a person might.
    let typed = code.to_lowercase().replace('-', " ");
    let out = restored.ok(&["recover"], &[&typed, NEW_PASSWORD, NEW_PASSWORD]);
    assert!(out.contains("password: restored"), "{out}");
    assert!(out.contains("totp:    restored"), "{out}");

    restored.fails(&["list"], &[PASSWORD]);
    let out = restored.ok(&["get", &login_id, "--reveal"], &[NEW_PASSWORD]);
    assert!(out.contains("password: login-password"), "{out}");
    let out = restored.ok(&["totp", &totp_id], &[]);
    assert!(out.contains("(valid for "), "{out}");

    // The restored copy is a new device; the old one is revoked in its registry.
    let out = restored.ok(&["devices"], &[]);
    assert!(
        out.contains("revoked") && out.contains("this device"),
        "{out}"
    );
    assert!(out.contains("2 device(s)"), "{out}");
    assert!(cli.ok(&["devices"], &[]).contains("1 device(s)"));

    // The original device is unaffected.
    assert!(cli.ok(&["list"], &[PASSWORD]).contains("1 item(s)"));
}

/// Pairing and sync between two vault files through the real binaries and the
/// real local network (mDNS + TCP), both "devices" being on this machine.
///
/// Needs a network interface with a private address and working multicast,
/// which CI machines do not reliably have:
///
/// ```text
/// cargo test -p zp-cli --test e2e -- --ignored
/// ```
#[test]
#[ignore = "needs a local network interface with multicast"]
fn two_vaults_pair_and_sync_on_the_local_network() {
    use std::io::{BufRead, BufReader, Read};

    let pc = Cli::new();
    pc.ok(&["init"], &[PASSWORD, PASSWORD]);
    let from_pc = added_id(&pc.ok(
        &["add", "login", "--title", "From the PC"],
        &[PASSWORD, "pc-password"],
    ));
    let totp_id = added_id(&pc.ok(&["add", "totp"], &[TOTP_URI]));

    // The PC shows a pairing code and waits. Its prompts are answered in order:
    // the master password, then the confirmation of the new device. (Locked
    // first: the daemon still holds what `add` unlocked.)
    pc.ok(&["lock"], &[]);
    let mut pairing = Command::new(env!("CARGO_BIN_EXE_zp-cli"))
        .arg("--vault")
        .arg(&pc.vault)
        .args(["--insecure-software-keystore", "pair"])
        .env_remove("ZEROPASS_VAULT")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = pairing.stdin.take().unwrap();
    writeln!(stdin, "{PASSWORD}").unwrap();
    writeln!(stdin, "y").unwrap();
    let mut stdout = BufReader::new(pairing.stdout.take().unwrap());
    let code = loop {
        let mut line = String::new();
        assert!(
            stdout.read_line(&mut line).unwrap() > 0,
            "`pair` ended without showing a code"
        );
        if line.starts_with("ZP1:") {
            break line.trim().to_owned();
        }
    };

    // The phone joins with the code and its own master password.
    let phone = Cli::new();
    let joined = phone.run(
        &["join", "--name", "Test phone"],
        &[NEW_PASSWORD, NEW_PASSWORD, &code],
    );
    if !joined.success {
        // Show the other side too: why the pairing failed is often there.
        let _ = pairing.kill();
        let mut rest = String::new();
        let _ = stdout.read_to_string(&mut rest);
        let mut errors = String::new();
        let _ = pairing.stderr.take().unwrap().read_to_string(&mut errors);
        panic!(
            "join failed: {}\n--- pair, output:\n{rest}\n--- pair, errors:\n{errors}",
            joined.stderr
        );
    }
    let out = joined.stdout;
    assert!(out.contains("joined vault"), "{out}");
    assert!(out.contains("as \"Test phone\""), "{out}");
    assert!(out.contains("totp:    available"), "{out}");
    assert!(
        out.contains("first sync: sent 0 change(s), received 2"),
        "{out}"
    );

    let mut rest = String::new();
    stdout.read_to_string(&mut rest).unwrap();
    assert!(pairing.wait().unwrap().success());
    assert!(rest.contains("added device \"Test phone\""), "{rest}");
    drop(stdin);

    // The phone has the PC's items and opens them with its own credentials.
    let out = phone.ok(&["get", &from_pc, "--reveal"], &[NEW_PASSWORD]);
    assert!(out.contains("password: pc-password"), "{out}");
    assert!(phone.ok(&["totp", &totp_id], &[]).contains("(valid for "));
    phone.ok(&["lock"], &[]);
    phone.fails(&["list"], &[PASSWORD]);
    // The code cannot be used a second time.
    let other = Cli::new();
    other.fails(&["join"], &[NEW_PASSWORD, NEW_PASSWORD, &code]);
    assert!(!other.vault.exists());

    // Later changes travel with `sync`, run on both devices at the same time.
    let from_phone = added_id(&phone.ok(
        &["add", "login", "--title", "From the phone"],
        &[NEW_PASSWORD, "phone-password"],
    ));
    pc.ok(&["delete", &from_pc], &[PASSWORD]);
    let pc_sync = Command::new(env!("CARGO_BIN_EXE_zp-cli"))
        .arg("--vault")
        .arg(&pc.vault)
        .args(["--insecure-software-keystore", "sync", "--seconds", "15"])
        .env_remove("ZEROPASS_VAULT")
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

    let out = pc.ok(&["get", &from_phone, "--reveal"], &[PASSWORD]);
    assert!(out.contains("password: phone-password"), "{out}");
    phone.fails(&["get", &from_pc], &[NEW_PASSWORD]);
    for cli in [&pc, &phone] {
        let out = cli.ok(&["devices"], &[]);
        assert!(
            out.contains("2 device(s)") && out.contains("Test phone"),
            "{out}"
        );
    }

    // The PC revokes the phone: its keys are replaced, and the phone, although it
    // still has its vault file and password, is refused and cannot follow.
    let phone_id = pc
        .ok(&["devices"], &[])
        .lines()
        .find(|line| line.contains("Test phone"))
        .and_then(|line| line.split_whitespace().next())
        .unwrap()
        .to_owned();
    pc.ok(&["lock"], &[]);
    let stderr = pc.fails(&["revoke", &phone_id[..8]], &[PASSWORD, "n"]);
    assert!(stderr.contains("nothing was changed"), "{stderr}");
    pc.ok(&["lock"], &[]);
    let out = pc.ok(&["revoke", &phone_id[..8]], &[PASSWORD, "y"]);
    assert!(out.contains("revoked device \"Test phone\""), "{out}");
    let out = pc.ok(&["devices"], &[]);
    assert!(
        out.contains("revoked") && out.contains("2 device(s)"),
        "{out}"
    );
    let stderr = pc.fails(&["revoke", &phone_id], &[PASSWORD, "y"]);
    assert!(stderr.contains("already been revoked"), "{stderr}");

    pc.ok(&["lock"], &[]);
    let secret = added_id(&pc.ok(
        &["add", "login", "--title", "after-revocation"],
        &[PASSWORD, "post-revocation-password"],
    ));
    let out = pc.ok(&["get", &secret, "--reveal"], &[PASSWORD]);
    assert!(out.contains("password: post-revocation-password"), "{out}");
    // The phone finds nobody to sync with any more.
    let phone_out = phone.ok(&["sync", "--seconds", "3"], &[]);
    assert!(!phone_out.contains("synced with \""), "{phone_out}");
    phone.fails(&["get", &secret], &[NEW_PASSWORD]);
}

#[test]
fn nearby_commands_fail_cleanly_without_a_partner() {
    let cli = Cli::new();
    // Joining needs a valid code; nothing is created without one.
    let stderr = cli.fails(&["join"], &[PASSWORD, PASSWORD, "not a pairing code"]);
    assert!(stderr.contains("not a valid pairing code"), "{stderr}");
    assert!(!cli.vault.exists());
    assert!(!cli.vault.with_extension("devkey").exists());

    // A vault with a single device has nobody to sync with.
    cli.ok(&["init"], &[PASSWORD, PASSWORD]);
    let out = cli.ok(&["sync", "--seconds", "1"], &[]);
    assert!(out.contains("no other devices yet"), "{out}");
    // An existing vault cannot be joined over.
    let stderr = cli.fails(&["join"], &[PASSWORD, PASSWORD, "ZP1:AAAA"]);
    assert!(stderr.contains("already exists"), "{stderr}");
}

#[test]
fn an_encrypted_export_moves_everything_to_another_vault() {
    let source = Cli::new();
    source.ok(&["init"], &[PASSWORD, PASSWORD]);
    let bank = added_id(&source.ok(
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
    source.ok(&["add", "totp", "--login", &bank], &[TOTP_URI]);
    source.ok(
        &["add", "note", "--title", "Wi-Fi"],
        &["purple monkey dishwasher"],
    );

    let export = source.vault.with_extension("zpexport");
    let export_arg = export.to_str().unwrap();
    // The passphrase is asked twice and must be long enough.
    let refused = source.run(&["export", export_arg], &["short", "short"]);
    assert!(!refused.success);
    let done = source.ok(
        &["export", export_arg],
        &["an export passphrase", "an export passphrase"],
    );
    assert!(
        done.contains("exported 1 login(s), 1 note(s), 1 one-time code(s)"),
        "{done}"
    );
    // Encrypted: nothing of the items is in the file.
    for secret in [
        "bank password",
        "purple monkey",
        "bank.example.com",
        "GEZDGNBV",
    ] {
        assert!(
            !file_contains(&export, secret),
            "{secret} is readable in the export"
        );
    }
    // An existing file is not replaced without --force.
    source.fails(&["export", export_arg], &[]);

    let target = Cli::new();
    target.ok(&["init"], &[PASSWORD, PASSWORD]);
    target.fails(&["import", export_arg], &[PASSWORD, "a wrong passphrase!"]);
    let imported = target.ok(&["import", export_arg], &["an export passphrase"]);
    assert!(
        imported.contains("imported 1 login(s), 1 note(s), 1 one-time code(s)"),
        "{imported}"
    );
    let listed = target.ok(&["list"], &[]);
    assert!(
        listed.contains("Bank") && listed.contains("Wi-Fi"),
        "{listed}"
    );
    // The one-time codes came along, still tied to the login.
    let totp_list = target.ok(&["list", "--domain", "totp"], &[]);
    let totp_id = totp_list.split_whitespace().next().unwrap();
    let shown = target.ok(&["get", totp_id], &[]);
    assert!(shown.contains("login:"), "{shown}");
    let code = target.ok(&["totp", totp_id], &[]);
    assert!(
        code.split_whitespace()
            .next()
            .unwrap()
            .chars()
            .all(|c| c.is_ascii_digit()),
        "{code}"
    );
}

#[test]
fn exports_of_other_password_managers_are_imported() {
    let cli = Cli::new();
    cli.ok(&["init"], &[PASSWORD, PASSWORD]);
    let dir = cli.vault.parent().unwrap();
    let chrome = dir.join("chrome.csv");
    std::fs::write(
        &chrome,
        "name,url,username,password,note\nShop,https://shop.example.com,dave,shop password,\n",
    )
    .unwrap();
    let bitwarden = dir.join("bitwarden.json");
    std::fs::write(
        &bitwarden,
        r#"{"encrypted":false,"items":[
            {"type":1,"name":"Mail","login":{"username":"bob","password":"mail password",
             "totp":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ","uris":[{"uri":"https://mail.example.org"}]}},
            {"type":2,"name":"Door code","notes":"1234"}]}"#,
    )
    .unwrap();

    let out = cli.ok(&["import", chrome.to_str().unwrap()], &[PASSWORD]);
    assert!(
        out.contains("Chrome / Edge (CSV): 1 login(s)") && out.contains("added 1 login(s)"),
        "{out}"
    );
    let out = cli.ok(&["import", bitwarden.to_str().unwrap()], &[]);
    assert!(
        out.contains("added 1 login(s), 1 note(s), 1 one-time code(s)"),
        "{out}"
    );
    let listed = cli.ok(&["list"], &[]);
    assert!(
        listed.contains("Shop") && listed.contains("Mail") && listed.contains("Door code"),
        "{listed}"
    );
    let shop = listed.lines().find(|line| line.contains("Shop")).unwrap();
    let shown = cli.ok(
        &["get", shop.split_whitespace().next().unwrap(), "--reveal"],
        &[],
    );
    assert!(
        shown.contains("shop password") && shown.contains("https://shop.example.com"),
        "{shown}"
    );
}

#[test]
fn init_creates_the_folder_of_a_new_vault() {
    let mut cli = Cli::new();
    // A folder that is not there yet, two levels deep.
    cli.vault = cli
        ._dir
        .path()
        .join("not")
        .join("there")
        .join("new.zpvault");
    let out = cli.ok(&["init"], &[PASSWORD, PASSWORD]);
    assert!(out.contains("created vault"), "{out}");
    assert!(cli.vault.exists());
    // ...and a command for a vault that is not there creates nothing.
    let missing = cli._dir.path().join("elsewhere").join("none.zpvault");
    let other = Cli {
        vault: missing.clone(),
        _dir: tempfile::tempdir().unwrap(),
    };
    let err = other.fails(&["list"], &[]);
    assert!(err.contains("no vault file"), "{err}");
    assert!(!missing.parent().unwrap().exists());
}

#[test]
fn join_replace_requires_confirmation_and_keeps_vault_on_decline() {
    let cli = Cli::new();
    cli.ok(&["init"], &[PASSWORD, PASSWORD]);
    let login_id = added_id(&cli.ok(
        &["add", "login", "--title", "KeepMe"],
        &[PASSWORD, "keep-secret"],
    ));

    // Without --replace, join refuses to overwrite an existing vault.
    let err = cli.fails(&["join"], &[]);
    assert!(err.contains("already exists"), "{err}");

    // With --replace, declining keeps the existing vault untouched.
    let err = cli.fails(&["join", "--replace"], &["n"]);
    assert!(err.contains("nothing was changed"), "{err}");
    let kept = cli.ok(&["get", &login_id, "--reveal"], &[PASSWORD]);
    assert!(kept.contains("keep-secret"), "{kept}");
}

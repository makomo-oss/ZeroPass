//! End-to-end test of the command-line client: runs the real binary against a
//! vault file in a temporary directory, feeding prompts through standard input.

#![allow(clippy::unwrap_used, reason = "test helpers may panic")]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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
            writeln!(stdin, "{line}").unwrap();
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
    let note_id = added_id(&cli.ok(
        &["add", "note", "--title", "Wi-Fi"],
        &[PASSWORD, "the wifi passphrase"],
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

    // totp
    let out = cli.ok(&["totp", &totp_id], &[]);
    let code = out.split_whitespace().next().unwrap();
    assert!(
        code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()),
        "{out}"
    );
    assert!(out.contains("(valid for "), "{out}");

    // wrong master password and unknown items
    let stderr = cli.fails(&["list"], &["not the master password"]);
    assert!(stderr.contains("wrong master password"), "{stderr}");
    let stderr = cli.fails(&["get", &"0".repeat(32)], &[PASSWORD]);
    assert!(stderr.contains("does not exist"), "{stderr}");

    // unlock / lock inside one shell session
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
    cli.fails(&["list"], &[PASSWORD]);
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

    let output = Command::new(env!("CARGO_BIN_EXE_zp-cli"))
        .arg("list")
        .env_remove("ZEROPASS_VAULT")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no vault file given"));
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

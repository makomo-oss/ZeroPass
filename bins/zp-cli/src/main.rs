//! ZeroPass command-line client.
//!
//! The vault is held by the vault daemon (`zp-vaultd`): this program asks it
//! over the local IPC and starts it when it is not running. What a command
//! unlocks stays unlocked in the daemon until it is locked or times out, so the
//! next command does not ask again.
//!
//! Pairing and sync (`pair`, `join`, `sync`) still open the vault file
//! themselves; they move behind the daemon together with `zp-syncd` (P3-05).

mod nearby;
mod remote;

use std::error::Error;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use zeroize::Zeroizing;
use zp_crypto::{
    DomainId, HardwareKeyError, HardwareKeyStore, InsecureSoftwareKeyStore, ItemId, Passkey, Totp,
};
use zp_vault::{AutoLock, Vault, VaultError};

use remote::{Remote, Start};

type CliResult<T> = Result<T, Box<dyn Error>>;

#[derive(Parser)]
#[command(name = "zp-cli", version, about = "ZeroPass command-line client")]
struct Cli {
    /// Path of the vault file.
    #[arg(long, env = "ZEROPASS_VAULT", global = true)]
    vault: Option<PathBuf>,

    /// DEVELOPMENT ONLY: protect the TOTP and passkey domains with a key stored in
    /// a file next to the vault instead of a hardware key store. No biometrics.
    #[arg(long, global = true)]
    insecure_software_keystore: bool,

    /// Do not use the platform's hardware key store (Windows Hello, ...). A vault
    /// created this way has no TOTP and passkey domains.
    #[arg(long, global = true, conflicts_with = "insecure_software_keystore")]
    no_hardware_keystore: bool,

    /// DEVELOPMENT ONLY: if this command starts the vault daemon, start it as an
    /// ordinary process instead of in a sandbox without network access.
    #[arg(long, global = true)]
    no_sandbox: bool,

    #[command(subcommand)]
    command: TopCommand,
}

/// Which key store protects the TOTP and passkey domains.
#[derive(Clone, Copy, PartialEq, Eq)]
enum KeyStoreChoice {
    /// The platform's hardware key store, if this device has one.
    Platform,
    /// None: password domain only.
    None,
    /// The development-only software key store.
    InsecureSoftware,
}

impl KeyStoreChoice {
    fn from_flags(cli: &Cli) -> Self {
        if cli.insecure_software_keystore {
            KeyStoreChoice::InsecureSoftware
        } else if cli.no_hardware_keystore {
            KeyStoreChoice::None
        } else {
            KeyStoreChoice::Platform
        }
    }
}

#[derive(Subcommand)]
enum TopCommand {
    /// Create a new vault.
    Init,
    /// Restore access to a vault file with its recovery key: sets a new master
    /// password and re-binds the TOTP and passkey domains to this device.
    Recover,
    /// Join an existing vault from this device: enter the pairing code that
    /// `pair` shows on a device which already has the vault.
    Join {
        /// The name of this device, shown to the user of the other device.
        #[arg(long)]
        name: Option<String>,
    },
    /// Open an interactive session; everything is locked when it ends.
    Shell,
    /// Inspect or stop the vault daemon.
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },
    #[command(flatten)]
    Session(Command),
}

#[derive(Subcommand)]
enum DaemonAction {
    /// Show whether the daemon is running and which domains are unlocked.
    Status,
    /// Start the daemon if it is not running.
    Start,
    /// Lock everything and stop the daemon.
    Stop,
}

/// One line typed in the shell.
#[derive(Parser)]
#[command(no_binary_name = true, name = "", disable_version_flag = true)]
struct ShellLine {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Unlock a domain (default: password).
    Unlock {
        #[arg(value_enum, default_value_t = DomainArg::Password)]
        domain: DomainArg,
    },
    /// Lock one domain, or all of them.
    Lock {
        #[arg(value_enum)]
        domain: Option<DomainArg>,
    },
    /// Add an item. Secrets are prompted for, never passed as arguments.
    Add {
        #[command(subcommand)]
        kind: AddKind,
    },
    /// Show an item.
    Get {
        /// Item identifier (32 hex digits).
        id: String,
        /// Print secret fields instead of masking them.
        #[arg(long)]
        reveal: bool,
    },
    /// List the items of a domain.
    List {
        #[arg(long, value_enum, default_value_t = DomainArg::Password)]
        domain: DomainArg,
    },
    /// Print the current one-time code of a TOTP entry.
    Totp {
        /// Item identifier (32 hex digits).
        id: String,
    },
    /// Delete an item.
    Delete {
        /// Item identifier (32 hex digits).
        id: String,
    },
    /// Create a recovery kit and print the recovery key to write down.
    RecoveryKit {
        /// Replace an existing kit; the previous recovery key stops working.
        #[arg(long)]
        replace: bool,
    },
    /// Show a pairing code and admit the device that enters it.
    Pair,
    /// Sync with the other devices of this vault on the local network.
    Sync {
        /// How long to look for other devices, in seconds.
        #[arg(long, default_value_t = 10)]
        seconds: u64,
    },
    /// List the devices of this vault.
    Devices,
    /// Revoke a lost or retired device and replace the vault keys.
    Revoke {
        /// The device identifier as shown by `devices`, or the start of it.
        device: String,
    },
    /// Change the master password.
    Passwd,
}

#[derive(Subcommand)]
enum AddKind {
    /// A login; the password is prompted for.
    Login {
        #[arg(long)]
        title: String,
        #[arg(long, default_value = "")]
        username: String,
        #[arg(long)]
        url: Vec<String>,
    },
    /// A secure note; the text is prompted for.
    Note {
        #[arg(long)]
        title: String,
    },
    /// A TOTP entry; the otpauth:// URI is prompted for.
    Totp {
        /// The login this entry belongs to.
        #[arg(long)]
        login: Option<String>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum DomainArg {
    Password,
    Totp,
    Passkey,
}

impl From<DomainArg> for DomainId {
    fn from(domain: DomainArg) -> Self {
        match domain {
            DomainArg::Password => DomainId::Password,
            DomainArg::Totp => DomainId::Totp,
            DomainArg::Passkey => DomainId::Passkey,
        }
    }
}

fn domain_name(domain: DomainId) -> &'static str {
    match domain {
        DomainId::Password => "password",
        DomainId::Totp => "totp",
        DomainId::Passkey => "passkey",
    }
}

/// Terminal input. Secrets are read without echo from a terminal; when standard
/// input is redirected (scripts, tests) every prompt reads one line from it.
struct Input {
    interactive: bool,
}

impl Input {
    fn new() -> Self {
        Self {
            interactive: io::stdin().is_terminal(),
        }
    }

    fn read_line() -> io::Result<Option<String>> {
        let mut line = String::new();
        if io::stdin().lock().read_line(&mut line)? == 0 {
            return Ok(None);
        }
        Ok(Some(line.trim_end_matches(['\r', '\n']).to_owned()))
    }

    fn secret(&self, prompt: &str) -> CliResult<Zeroizing<String>> {
        if self.interactive {
            return Ok(Zeroizing::new(rpassword::prompt_password(prompt)?));
        }
        let line = Self::read_line()?.ok_or("unexpected end of input")?;
        Ok(Zeroizing::new(line))
    }

    fn line(&self, prompt: &str) -> CliResult<Option<String>> {
        if self.interactive {
            let mut err = io::stderr().lock();
            write!(err, "{prompt}")?;
            err.flush()?;
        }
        Ok(Self::read_line()?)
    }

    fn new_master_password(&self) -> CliResult<Zeroizing<String>> {
        let password = self.secret("New master password: ")?;
        let again = self.secret("Repeat master password: ")?;
        if *password != *again {
            return Err("the passwords do not match".into());
        }
        Ok(password)
    }
}

fn dev_key_path(vault: &Path) -> PathBuf {
    vault.with_extension("devkey")
}

/// Sets up the hardware key store for the TOTP and passkey domains.
fn hardware_key_store(
    choice: KeyStoreChoice,
    vault: &Path,
    create: bool,
) -> CliResult<Option<Box<dyn HardwareKeyStore>>> {
    match choice {
        KeyStoreChoice::None => return Ok(None),
        KeyStoreChoice::Platform => {
            return match zp_hwkey::platform_key_store(create) {
                Ok(store) => Ok(Some(store)),
                // No biometrics on this device: carry on with the password domain only.
                Err(HardwareKeyError::Unavailable(reason)) => {
                    if create {
                        writeln!(io::stderr(), "note: no hardware key store ({reason})")?;
                    }
                    Ok(None)
                }
                Err(error) => Err(error.into()),
            };
        }
        KeyStoreChoice::InsecureSoftware => {}
    }
    let path = dev_key_path(vault);
    writeln!(
        io::stderr(),
        "warning: using the INSECURE software key store ({}); TOTP and passkey data are NOT protected by biometrics",
        path.display()
    )?;
    let store = if create {
        let store = InsecureSoftwareKeyStore::generate()?;
        std::fs::write(&path, store.key_bytes().as_slice())?;
        store
    } else {
        let bytes =
            Zeroizing::new(std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?);
        let key: &[u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| "the software key store file is malformed")?;
        InsecureSoftwareKeyStore::from_key_bytes(key)
    };
    Ok(Some(Box::new(store)))
}

fn parse_id(text: &str) -> CliResult<ItemId> {
    let invalid = || "an item identifier is 32 hexadecimal digits";
    if text.len() != 32 || !text.is_ascii() {
        return Err(invalid().into());
    }
    let mut bytes = [0u8; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).map_err(|_| invalid())?;
    }
    Ok(ItemId::from_bytes(bytes))
}

struct Session {
    path: PathBuf,
    vault: Vault,
    hardware: Option<Box<dyn HardwareKeyStore>>,
    input: Input,
}

impl Session {
    /// Unlocks every domain of the vault and keeps them unlocked until this
    /// command ends, for commands that need all of them after waiting for
    /// someone: the idle timeout of the hardware-bound domains (one minute) is
    /// shorter than a pairing code lives.
    fn unlock_every_domain(&mut self) -> CliResult<()> {
        for domain in DomainId::ALL {
            if self.vault.has_domain(domain)? {
                self.ensure_unlocked(domain)?;
            }
        }
        self.vault.set_auto_lock(AutoLock {
            password: None,
            hardware: None,
        });
        Ok(())
    }

    /// Makes sure `domain` is unlocked, prompting if necessary.
    fn ensure_unlocked(&mut self, domain: DomainId) -> CliResult<()> {
        if self.vault.is_unlocked(domain) {
            return Ok(());
        }
        if domain == DomainId::Password {
            let password = self.input.secret("Master password: ")?;
            self.vault.unlock_password(&password)?;
            return Ok(());
        }
        if !self.vault.has_domain(domain)? {
            return Err(format!(
                "this vault has no {} domain (it was created without a hardware key store)",
                domain_name(domain)
            )
            .into());
        }
        let hardware = self
            .hardware
            .as_deref()
            .ok_or("no hardware key store is available to unlock this domain")?;
        match domain {
            DomainId::Totp => self.vault.unlock_hardware::<Totp>(hardware)?,
            _ => self.vault.unlock_hardware::<Passkey>(hardware)?,
        }
        Ok(())
    }

    /// Opens the vault file directly, for the commands that do not go through
    /// the daemon yet.
    fn open(choice: KeyStoreChoice, path: &Path) -> CliResult<Self> {
        Ok(Self {
            vault: Vault::open(path)?,
            path: path.to_path_buf(),
            hardware: hardware_key_store(choice, path, false)?,
            input: Input::new(),
        })
    }
}

/// Whether a command is carried out by this process on the vault file, rather
/// than by the daemon.
fn is_direct(command: &Command) -> bool {
    matches!(command, Command::Pair | Command::Sync { .. })
}

/// Runs a command that works on the vault file itself.
fn run_direct(
    choice: KeyStoreChoice,
    vault_path: &Path,
    command: Command,
    out: &mut impl Write,
) -> CliResult<()> {
    let mut session = Session::open(choice, vault_path)?;
    match command {
        Command::Pair => session.pair(out),
        Command::Sync { seconds } => session.sync(seconds, out),
        _ => unreachable!("not a direct command"),
    }
}

fn mask(secret: &str, reveal: bool) -> &str {
    if reveal {
        secret
    } else {
        "********  (use --reveal to show)"
    }
}

/// Splits a shell line into words; double quotes group words containing spaces.
fn split_words(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut pending = false;
    for ch in line.chars() {
        match ch {
            '"' => {
                quoted = !quoted;
                pending = true;
            }
            ch if ch.is_whitespace() && !quoted => {
                if pending {
                    words.push(std::mem::take(&mut current));
                    pending = false;
                }
            }
            ch => {
                current.push(ch);
                pending = true;
            }
        }
    }
    if pending {
        words.push(current);
    }
    words
}

fn shell(choice: KeyStoreChoice, vault_path: &Path, out: &mut impl Write) -> CliResult<()> {
    let mut remote = Remote::open(vault_path, choice)?;
    writeln!(
        out,
        "ZeroPass shell. Type `help` for commands, `exit` to leave."
    )?;
    while let Some(line) = remote.input.line("zp> ")? {
        let words = split_words(&line);
        match words.first().map(String::as_str) {
            None => continue,
            Some("exit" | "quit") => break,
            _ => {}
        }
        match ShellLine::try_parse_from(&words) {
            Ok(parsed) => {
                let result = if is_direct(&parsed.command) {
                    run_direct(choice, vault_path, parsed.command, out)
                } else {
                    remote.run(parsed.command, out)
                };
                if let Err(error) = result {
                    writeln!(out, "error: {error}")?;
                }
            }
            // Covers `help` and usage errors.
            Err(error) => writeln!(out, "{}", error.render())?,
        }
    }
    remote.run(Command::Lock { domain: None }, &mut io::sink())
}

fn warn_about_software_key_store(choice: KeyStoreChoice, vault_path: &Path) -> io::Result<()> {
    if choice == KeyStoreChoice::InsecureSoftware {
        writeln!(
            io::stderr(),
            "warning: using the INSECURE software key store ({}); TOTP and passkey data are NOT protected by biometrics",
            dev_key_path(vault_path).display()
        )?;
    }
    Ok(())
}

fn init(choice: KeyStoreChoice, vault_path: &Path, out: &mut impl Write) -> CliResult<()> {
    if vault_path.exists() {
        return Err(VaultError::AlreadyExists.into());
    }
    let password = Input::new().new_master_password()?;
    warn_about_software_key_store(choice, vault_path)?;
    Remote::open_with(vault_path, choice, Start::Always)?.init(vault_path, &password, out)
}

fn recover(choice: KeyStoreChoice, vault_path: &Path, out: &mut impl Write) -> CliResult<()> {
    if !vault_path.exists() {
        return Err(VaultError::NotFound.into());
    }
    let input = Input::new();
    let code = input.secret("Recovery key: ")?;
    let password = input.new_master_password()?;
    warn_about_software_key_store(choice, vault_path)?;
    Remote::open(vault_path, choice)?.recover(&code, &password, out)
}

fn daemon(
    choice: KeyStoreChoice,
    vault_path: &Path,
    action: &DaemonAction,
    out: &mut impl Write,
) -> CliResult<()> {
    let start = match action {
        DaemonAction::Start => Start::Always,
        DaemonAction::Status | DaemonAction::Stop => Start::Never,
    };
    let Some(client) = remote::connect(vault_path, choice, start)? else {
        writeln!(out, "the vault daemon is not running")?;
        return Ok(());
    };
    let mut remote = Remote::with(client);
    match action {
        DaemonAction::Status | DaemonAction::Start => remote.describe(out),
        DaemonAction::Stop => {
            remote.stop()?;
            writeln!(out, "the vault daemon was stopped")?;
            Ok(())
        }
    }
}

fn run(cli: Cli) -> CliResult<()> {
    let vault_path = cli
        .vault
        .clone()
        .ok_or("no vault file given: pass --vault <PATH> or set ZEROPASS_VAULT")?;
    let mut out = io::stdout().lock();
    let choice = KeyStoreChoice::from_flags(&cli);
    if cli.no_sandbox {
        remote::disable_sandbox();
    }
    match cli.command {
        TopCommand::Init => init(choice, &vault_path, &mut out),
        TopCommand::Recover => recover(choice, &vault_path, &mut out),
        TopCommand::Join { name } => nearby::join(choice, &vault_path, name, &mut out),
        TopCommand::Shell => shell(choice, &vault_path, &mut out),
        TopCommand::Daemon { action } => daemon(choice, &vault_path, &action, &mut out),
        TopCommand::Session(command) if is_direct(&command) => {
            run_direct(choice, &vault_path, command, &mut out)
        }
        TopCommand::Session(command) => Remote::open(&vault_path, choice)?.run(command, &mut out),
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(io::stderr(), "error: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_are_split_on_whitespace_and_quotes() {
        assert_eq!(
            split_words("  list   --domain totp "),
            ["list", "--domain", "totp"]
        );
        assert_eq!(
            split_words(r#"add login --title "My Bank" --username """#),
            ["add", "login", "--title", "My Bank", "--username", ""]
        );
        assert!(split_words("   ").is_empty());
    }

    #[test]
    fn item_ids_are_parsed_strictly() {
        let id = ItemId::from_bytes([0xAB; 16]);
        assert_eq!(parse_id(&id.to_string()).unwrap(), id);
        for bad in [
            "",
            "abcd",
            &"g".repeat(32),
            &"a".repeat(33),
            &"é".repeat(16),
        ] {
            assert!(parse_id(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn command_line_is_well_formed() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
        ShellLine::command().debug_assert();
    }
}

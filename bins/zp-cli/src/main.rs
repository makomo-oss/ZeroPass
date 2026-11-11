//! ZeroPass command-line client.
//!
//! Until the vault daemon exists (Phase 3) this binary opens the vault file
//! directly. Nothing stays unlocked between invocations: each command prompts for
//! what it needs. `zp-cli shell` keeps one session open so that `unlock`, `lock`
//! and the idle auto-lock can be exercised.

mod nearby;

use std::error::Error;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use zeroize::Zeroizing;
use zp_crypto::{
    DomainId, HardwareKeyError, HardwareKeyStore, InsecureSoftwareKeyStore, ItemId, Passkey,
    Password, RecoveryKey, Totp,
};
use zp_vault::model::{Content, Login, SecureNote};
use zp_vault::{CreateOptions, KdfChoice, Vault, VaultError, totp};

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
    /// Open an interactive session in which domains stay unlocked until locked.
    Shell,
    #[command(flatten)]
    Session(Command),
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

    fn content(&mut self, id: ItemId) -> CliResult<Content> {
        let domain = self
            .vault
            .item_domain(id)?
            .ok_or(VaultError::ItemNotFound)?;
        self.ensure_unlocked(domain)?;
        Ok(match domain {
            DomainId::Password => self.vault.get_content::<Password>(id)?,
            DomainId::Totp => self.vault.get_content::<Totp>(id)?,
            DomainId::Passkey => self.vault.get_content::<Passkey>(id)?,
        })
    }

    fn run(&mut self, command: Command, out: &mut impl Write) -> CliResult<()> {
        match command {
            Command::Unlock { domain } => {
                let domain = DomainId::from(domain);
                self.ensure_unlocked(domain)?;
                writeln!(out, "unlocked: {}", domain_name(domain))?;
            }
            Command::Lock {
                domain: Some(domain),
            } => {
                self.vault.lock(domain.into());
                writeln!(out, "locked: {}", domain_name(domain.into()))?;
            }
            Command::Lock { domain: None } => {
                self.vault.lock_all();
                writeln!(out, "locked: all domains")?;
            }
            Command::Add { kind } => {
                let id = self.add(kind)?;
                writeln!(out, "added {id}")?;
            }
            Command::Get { id, reveal } => {
                let content = self.content(parse_id(&id)?)?;
                print_content(out, &content, reveal)?;
            }
            Command::List { domain } => {
                let domain = DomainId::from(domain);
                self.ensure_unlocked(domain)?;
                let mut items = match domain {
                    DomainId::Password => self.vault.list::<Password>()?,
                    DomainId::Totp => self.vault.list::<Totp>()?,
                    DomainId::Passkey => self.vault.list::<Passkey>()?,
                };
                items.sort_by(|a, b| a.1.title().cmp(b.1.title()).then(a.0.cmp(&b.0)));
                for (id, content) in &items {
                    writeln!(
                        out,
                        "{id}  {:<10}  {}",
                        format!("{:?}", content.kind()),
                        content.title()
                    )?;
                }
                writeln!(out, "{} item(s)", items.len())?;
            }
            Command::Totp { id } => {
                self.ensure_unlocked(DomainId::Totp)?;
                let code = self.vault.totp_code(parse_id(&id)?)?;
                writeln!(
                    out,
                    "{} (valid for {}s)",
                    code.as_str(),
                    code.seconds_remaining()
                )?;
            }
            Command::Delete { id } => {
                let id = parse_id(&id)?;
                let domain = self
                    .vault
                    .item_domain(id)?
                    .ok_or(VaultError::ItemNotFound)?;
                self.ensure_unlocked(domain)?;
                match domain {
                    DomainId::Password => self.vault.delete::<Password>(id)?,
                    DomainId::Totp => self.vault.delete::<Totp>(id)?,
                    DomainId::Passkey => self.vault.delete::<Passkey>(id)?,
                }
                writeln!(out, "deleted {id}")?;
            }
            Command::RecoveryKit { replace } => {
                if self.vault.has_recovery_kit()? && !replace {
                    return Err("a recovery kit already exists; pass --replace to create a new one and invalidate the old recovery key".into());
                }
                for domain in DomainId::ALL {
                    if self.vault.has_domain(domain)? {
                        self.ensure_unlocked(domain)?;
                    }
                }
                let recovery_key = self.vault.create_recovery_kit()?;
                writeln!(
                    out,
                    "Recovery key (write it down and keep it offline; it is shown only once):"
                )?;
                writeln!(out)?;
                writeln!(out, "    {}", recovery_key.to_code().as_str())?;
                writeln!(out)?;
                writeln!(
                    out,
                    "To recover you need this key AND a backup copy of the vault file."
                )?;
            }
            Command::Pair => self.pair(out)?,
            Command::Sync { seconds } => self.sync(seconds, out)?,
            Command::Devices => {
                let registry = self.vault.registry()?;
                let vector = self.vault.version_vector()?;
                let own = self.vault.device_id();
                for record in registry.records() {
                    let state = if registry.is_revoked(&record.device_id) {
                        "revoked"
                    } else if record.device_id == own {
                        "this device"
                    } else {
                        "active"
                    };
                    writeln!(
                        out,
                        "{}  {:<11}  {} change(s) held  {}",
                        record.device_id,
                        state,
                        vector.get(&record.device_id),
                        record.name
                    )?;
                }
                writeln!(out, "{} device(s)", registry.records().count())?;
            }
            Command::Passwd => {
                let current = self.input.secret("Current master password: ")?;
                let new = self.input.new_master_password()?;
                self.vault
                    .change_master_password(&current, &new, KdfChoice::default())?;
                writeln!(out, "master password changed")?;
            }
        }
        Ok(())
    }

    fn add(&mut self, kind: AddKind) -> CliResult<ItemId> {
        match kind {
            AddKind::Login {
                title,
                username,
                url,
            } => {
                self.ensure_unlocked(DomainId::Password)?;
                let password = self.input.secret("Password of the new login: ")?;
                let mut login = Login::new(title, username, password.as_str());
                login.urls = url;
                Ok(self.vault.insert(login)?)
            }
            AddKind::Note { title } => {
                self.ensure_unlocked(DomainId::Password)?;
                let body = self.input.secret("Note text: ")?;
                Ok(self.vault.insert(SecureNote::new(title, body.as_str()))?)
            }
            AddKind::Totp { login } => {
                let login = login.as_deref().map(parse_id).transpose()?;
                self.ensure_unlocked(DomainId::Totp)?;
                let uri = self.input.secret("otpauth:// URI: ")?;
                let mut entry = totp::parse_otpauth_uri(&uri)?;
                if let Some(login) = login {
                    entry = entry.for_login(login);
                }
                Ok(self.vault.insert(entry)?)
            }
        }
    }
}

fn mask(secret: &str, reveal: bool) -> &str {
    if reveal {
        secret
    } else {
        "********  (use --reveal to show)"
    }
}

fn print_content(out: &mut impl Write, content: &Content, reveal: bool) -> io::Result<()> {
    match content {
        Content::Login(login) => {
            writeln!(out, "kind:     login")?;
            writeln!(out, "title:    {}", login.title)?;
            writeln!(out, "username: {}", login.username)?;
            writeln!(out, "password: {}", mask(&login.password, reveal))?;
            for url in &login.urls {
                writeln!(out, "url:      {url}")?;
            }
            if !login.notes.is_empty() {
                writeln!(out, "notes:    {}", mask(&login.notes, reveal))?;
            }
        }
        Content::SecureNote(note) => {
            writeln!(out, "kind:  note")?;
            writeln!(out, "title: {}", note.title)?;
            writeln!(out, "text:  {}", mask(&note.body, reveal))?;
        }
        Content::Totp(entry) => {
            writeln!(out, "kind:    totp")?;
            writeln!(out, "issuer:  {}", entry.issuer)?;
            writeln!(out, "account: {}", entry.account)?;
            writeln!(out, "digits:  {}", entry.digits)?;
            writeln!(out, "period:  {}s", entry.period)?;
            if let Some(login) = entry.login() {
                writeln!(out, "login:   {login}")?;
            }
        }
        Content::Passkey(passkey) => {
            writeln!(out, "kind:  passkey")?;
            writeln!(out, "rp_id: {}", passkey.rp_id)?;
            writeln!(out, "user:  {}", passkey.user_name)?;
        }
    }
    Ok(())
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

fn shell(session: &mut Session, out: &mut impl Write) -> CliResult<()> {
    writeln!(
        out,
        "ZeroPass shell. Type `help` for commands, `exit` to leave."
    )?;
    while let Some(line) = session.input.line("zp> ")? {
        let words = split_words(&line);
        match words.first().map(String::as_str) {
            None => continue,
            Some("exit" | "quit") => break,
            _ => {}
        }
        match ShellLine::try_parse_from(&words) {
            Ok(parsed) => {
                if let Err(error) = session.run(parsed.command, out) {
                    writeln!(out, "error: {error}")?;
                }
            }
            // Covers `help` and usage errors.
            Err(error) => writeln!(out, "{}", error.render())?,
        }
    }
    session.vault.lock_all();
    Ok(())
}

fn init(choice: KeyStoreChoice, vault_path: &Path, out: &mut impl Write) -> CliResult<()> {
    if vault_path.exists() {
        return Err(VaultError::AlreadyExists.into());
    }
    let input = Input::new();
    let password = input.new_master_password()?;
    let hardware = hardware_key_store(choice, vault_path, true)?;
    let created = Vault::create(
        vault_path,
        &password,
        hardware.as_deref(),
        CreateOptions::default(),
    );
    let vault = match created {
        Ok(vault) => vault,
        Err(error) => {
            if choice == KeyStoreChoice::InsecureSoftware {
                let _ = std::fs::remove_file(dev_key_path(vault_path));
            }
            return Err(error.into());
        }
    };
    let params = vault.kdf_params()?;
    writeln!(out, "created vault {}", vault.vault_id())?;
    writeln!(out, "  file:    {}", vault_path.display())?;
    writeln!(
        out,
        "  argon2id: m={} KiB, t={}, p={}",
        params.m_kib(),
        params.t(),
        params.p()
    )?;
    for domain in DomainId::ALL {
        let state = if vault.has_domain(domain)? {
            "available"
        } else {
            "not available (no hardware key store)"
        };
        writeln!(out, "  {:<8} {state}", format!("{}:", domain_name(domain)))?;
    }
    Ok(())
}

fn recover(choice: KeyStoreChoice, vault_path: &Path, out: &mut impl Write) -> CliResult<()> {
    if !vault_path.exists() {
        return Err(VaultError::NotFound.into());
    }
    let input = Input::new();
    let code = input.secret("Recovery key: ")?;
    let recovery_key = RecoveryKey::from_code(&code)?;
    let password = input.new_master_password()?;
    let hardware = hardware_key_store(choice, vault_path, true)?;
    let mut vault = Vault::recover(
        vault_path,
        &recovery_key,
        &password,
        hardware.as_deref(),
        CreateOptions::default(),
    )?;
    writeln!(out, "recovered vault {}", vault.vault_id())?;
    for domain in DomainId::ALL {
        let state = if vault.is_unlocked(domain) {
            "restored"
        } else if vault.has_domain(domain)? {
            "NOT restored (no hardware key store on this device)"
        } else {
            "not part of this vault"
        };
        writeln!(out, "  {:<8} {state}", format!("{}:", domain_name(domain)))?;
    }
    Ok(())
}

fn run(cli: Cli) -> CliResult<()> {
    let vault_path = cli
        .vault
        .clone()
        .ok_or("no vault file given: pass --vault <PATH> or set ZEROPASS_VAULT")?;
    let mut out = io::stdout().lock();
    let choice = KeyStoreChoice::from_flags(&cli);
    if matches!(cli.command, TopCommand::Recover) {
        return recover(choice, &vault_path, &mut out);
    }
    if let TopCommand::Join { name } = &cli.command {
        return nearby::join(choice, &vault_path, name.clone(), &mut out);
    }
    if matches!(cli.command, TopCommand::Init) {
        return init(choice, &vault_path, &mut out);
    }
    let mut session = Session {
        vault: Vault::open(&vault_path)?,
        path: vault_path.clone(),
        hardware: hardware_key_store(choice, &vault_path, false)?,
        input: Input::new(),
    };
    match cli.command {
        TopCommand::Init | TopCommand::Recover | TopCommand::Join { .. } => {
            unreachable!("handled above")
        }
        TopCommand::Shell => shell(&mut session, &mut out),
        TopCommand::Session(command) => session.run(command, &mut out),
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

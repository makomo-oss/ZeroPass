//! Commands that are carried out by the vault daemon: this process asks over
//! the local IPC and never sees a vault key.

use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command as Process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use zp_crypto::DomainId;
use zp_ipc::proto::{self, ErrorCode, item, new_item, request, response};
use zp_ipc::{Client, DAEMON_NAME, DAEMON_SANDBOX, DaemonPolicy, Endpoint, IpcError};
use zp_sandbox::Access;
use zp_vault::VaultError;

use super::{
    AddKind, CliResult, Command, Input, KeyStoreChoice, clipboard, dev_key_path, domain_name, mask,
    parse_id,
};

/// How long a daemon that was just started may take to listen.
const START_TIMEOUT: Duration = Duration::from_secs(10);

/// Whether to start the daemon when it is not running.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Start {
    /// Start it only if the vault file exists: nothing else needs a daemon.
    IfVaultExists,
    /// Start it; the vault is about to be created.
    Always,
    /// Do not start it.
    Never,
}

fn to_proto(domain: DomainId) -> proto::Domain {
    match domain {
        DomainId::Password => proto::Domain::Password,
        DomainId::Totp => proto::Domain::Totp,
        DomainId::Passkey => proto::Domain::Passkey,
    }
}

fn from_proto(domain: i32) -> Option<DomainId> {
    match proto::Domain::try_from(domain).ok()? {
        proto::Domain::Password => Some(DomainId::Password),
        proto::Domain::Totp => Some(DomainId::Totp),
        proto::Domain::Passkey => Some(DomainId::Passkey),
        proto::Domain::Unspecified => None,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unexpected() -> Box<dyn std::error::Error> {
    "the vault daemon gave an unexpected answer".into()
}

/// Set by `--no-sandbox`: start the daemon as an ordinary process.
static NO_SANDBOX: AtomicBool = AtomicBool::new(false);

/// Makes this process start the daemon without the sandbox from now on.
pub(crate) fn disable_sandbox() {
    NO_SANDBOX.store(true, Ordering::Relaxed);
}

/// Gives the daemon's sandbox access to what the daemon works with, and to
/// nothing else: its executable, the vault file, and the files it creates
/// beside the vault (the database's journal).
fn grant_to_sandbox(executable: &Path, vault: &Path) -> io::Result<()> {
    zp_sandbox::allow(DAEMON_SANDBOX, executable, Access::ReadExecute)?;
    if let Some(directory) = vault.parent() {
        zp_sandbox::allow(DAEMON_SANDBOX, directory, Access::CreateFiles)?;
    }
    // Files that are already there are not covered by the grant on the
    // directory.
    let mut journal = vault.as_os_str().to_owned();
    journal.push("-journal");
    for existing in [
        vault.to_path_buf(),
        PathBuf::from(journal),
        dev_key_path(vault),
    ] {
        if existing.exists() {
            zp_sandbox::allow(DAEMON_SANDBOX, &existing, Access::Modify)?;
        }
    }
    Ok(())
}

/// Starts the daemon for `vault` as a background process: in a sandbox without
/// network access where the platform has one.
fn start_daemon(vault: &Path, choice: KeyStoreChoice) -> CliResult<()> {
    let name = format!("{DAEMON_NAME}{}", std::env::consts::EXE_SUFFIX);
    let executable = std::env::current_exe()?.with_file_name(name);
    let vault = std::path::absolute(vault)?;
    let mut args: Vec<OsString> = vec!["--vault".into(), vault.clone().into()];
    match choice {
        KeyStoreChoice::Platform => {}
        KeyStoreChoice::None => args.push("--no-hardware-keystore".into()),
        KeyStoreChoice::InsecureSoftware => args.push("--insecure-software-keystore".into()),
    }
    let started = if zp_sandbox::SUPPORTED && !NO_SANDBOX.load(Ordering::Relaxed) {
        grant_to_sandbox(&executable, &vault)
            .and_then(|()| zp_sandbox::spawn(DAEMON_SANDBOX, &executable, &args))
            .map(drop)
    } else {
        zp_ipc::spawn_detached(Process::new(&executable).args(&args))
    };
    started.map_err(|error| {
        format!(
            "cannot start the vault daemon ({}): {error}",
            executable.display()
        )
        .into()
    })
}

/// Connects to the daemon of `vault`, starting it if `start` says so.
/// `Ok(None)` means it is not running and was not to be started.
pub(crate) fn connect(
    vault: &Path,
    choice: KeyStoreChoice,
    start: Start,
) -> CliResult<Option<Client>> {
    let endpoint = Endpoint::for_vault(vault)?;
    let policy = DaemonPolicy::beside_current_exe()?;
    let attempt = || Client::connect(&endpoint, &policy, "zp-cli");
    match attempt() {
        Ok(client) => return Ok(Some(client)),
        Err(IpcError::NotRunning) => {}
        Err(error) => return Err(error.into()),
    }
    match start {
        Start::Never => return Ok(None),
        Start::IfVaultExists if !vault.exists() => return Err(VaultError::NotFound.into()),
        Start::IfVaultExists | Start::Always => {}
    }
    start_daemon(vault, choice)?;
    let deadline = Instant::now() + START_TIMEOUT;
    loop {
        thread::sleep(Duration::from_millis(20));
        match attempt() {
            Ok(client) => return Ok(Some(client)),
            Err(IpcError::NotRunning) if Instant::now() < deadline => {}
            Err(IpcError::NotRunning) => return Err("the vault daemon did not start".into()),
            Err(error) => return Err(error.into()),
        }
    }
}

/// A conversation with the vault daemon.
pub(crate) struct Remote {
    client: Client,
    pub(crate) input: Input,
}

impl Remote {
    /// Connects to the daemon of an existing vault, starting it if necessary.
    pub(crate) fn open(vault: &Path, choice: KeyStoreChoice) -> CliResult<Self> {
        Self::open_with(vault, choice, Start::IfVaultExists)
    }

    pub(crate) fn open_with(vault: &Path, choice: KeyStoreChoice, start: Start) -> CliResult<Self> {
        let client = connect(vault, choice, start)?.ok_or("the vault daemon is not running")?;
        Ok(Self::with(client))
    }

    /// Continues on an open connection.
    pub(crate) fn with(client: Client) -> Self {
        Self {
            client,
            input: Input::new(),
        }
    }

    fn call(&mut self, request: request::Body) -> Result<response::Body, IpcError> {
        self.client.call(request)
    }

    pub(crate) fn status(&mut self) -> CliResult<proto::StatusReply> {
        match self.call(request::Body::Status(proto::Status {}))? {
            response::Body::Status(status) => Ok(status),
            _ => Err(unexpected()),
        }
    }

    /// The state of the vault, which must exist.
    fn vault_status(&mut self) -> CliResult<proto::StatusReply> {
        let status = self.status()?;
        if !status.vault_exists {
            return Err(VaultError::NotFound.into());
        }
        Ok(status)
    }

    /// Unlocks `domain`. The master password is asked for here; the biometric
    /// prompt of the other domains is shown by the daemon.
    fn unlock(&mut self, domain: DomainId) -> CliResult<()> {
        let mut unlock = proto::Unlock {
            domain: to_proto(domain) as i32,
            master_password: String::new(),
        };
        if domain == DomainId::Password {
            let password = self.input.secret("Master password: ")?;
            unlock.master_password.push_str(&password);
        }
        self.call(request::Body::Unlock(unlock))?;
        Ok(())
    }

    /// Makes sure `domain` is unlocked, prompting if necessary.
    fn ensure_unlocked(&mut self, domain: DomainId) -> CliResult<()> {
        let status = self.vault_status()?;
        self.ensure_unlocked_in(&status, domain)
    }

    fn ensure_unlocked_in(
        &mut self,
        status: &proto::StatusReply,
        domain: DomainId,
    ) -> CliResult<()> {
        let state = status
            .domains
            .iter()
            .find(|state| from_proto(state.domain) == Some(domain))
            .copied()
            .unwrap_or_default();
        if !state.available {
            return Err(format!(
                "this vault has no {} domain (it was created without a hardware key store)",
                domain_name(domain)
            )
            .into());
        }
        if state.unlocked {
            return Ok(());
        }
        self.unlock(domain)
    }

    /// Unlocks every domain the vault has, for the operations that need all.
    fn unlock_every_domain(&mut self) -> CliResult<()> {
        let status = self.vault_status()?;
        for domain in DomainId::ALL {
            let available = status
                .domains
                .iter()
                .any(|state| from_proto(state.domain) == Some(domain) && state.available);
            if available {
                self.ensure_unlocked_in(&status, domain)?;
            }
        }
        Ok(())
    }

    /// Makes a request; if the daemon answers that a domain is locked, unlocks
    /// it and asks again.
    fn call_unlocking(&mut self, request: &request::Body) -> CliResult<response::Body> {
        // Each of the three domains may need unlocking once.
        for _ in 0..DomainId::ALL.len() {
            match self.call(request.clone()) {
                Err(IpcError::Remote(error)) if error.code == ErrorCode::Locked as i32 => {
                    let domain = error.domain.and_then(from_proto).ok_or_else(unexpected)?;
                    self.unlock(domain)?;
                }
                other => return Ok(other?),
            }
        }
        Ok(self.call(request.clone())?)
    }

    fn lock_all(&mut self) -> CliResult<()> {
        self.call(request::Body::Lock(proto::Lock { domain: None }))?;
        Ok(())
    }

    /// `init`: creates the vault.
    pub(crate) fn init(
        &mut self,
        vault: &Path,
        password: &str,
        out: &mut impl Write,
    ) -> CliResult<()> {
        let reply = self.call(request::Body::CreateVault(proto::CreateVault {
            master_password: password.to_owned(),
        }))?;
        let response::Body::Status(status) = reply else {
            return Err(unexpected());
        };
        // Creating a vault is not unlocking it: what follows asks again.
        self.lock_all()?;
        writeln!(out, "created vault {}", hex(&status.vault_id))?;
        writeln!(out, "  file:    {}", vault.display())?;
        for state in &status.domains {
            let Some(domain) = from_proto(state.domain) else {
                continue;
            };
            let availability = if state.available {
                "available"
            } else {
                "not available (no hardware key store)"
            };
            writeln!(
                out,
                "  {:<8} {availability}",
                format!("{}:", domain_name(domain))
            )?;
        }
        Ok(())
    }

    /// `recover`: restores access with the recovery key.
    pub(crate) fn recover(
        &mut self,
        recovery_key: &str,
        password: &str,
        out: &mut impl Write,
    ) -> CliResult<()> {
        let reply = self.call(request::Body::RecoverVault(proto::RecoverVault {
            recovery_key: recovery_key.to_owned(),
            new_master_password: password.to_owned(),
        }))?;
        let response::Body::Status(status) = reply else {
            return Err(unexpected());
        };
        self.lock_all()?;
        writeln!(out, "recovered vault {}", hex(&status.vault_id))?;
        for state in &status.domains {
            let Some(domain) = from_proto(state.domain) else {
                continue;
            };
            let outcome = if state.unlocked {
                "restored"
            } else if state.available {
                "NOT restored (no hardware key store on this device)"
            } else {
                "not part of this vault"
            };
            writeln!(
                out,
                "  {:<8} {outcome}",
                format!("{}:", domain_name(domain))
            )?;
        }
        Ok(())
    }

    /// `daemon status`.
    pub(crate) fn describe(&mut self, out: &mut impl Write) -> CliResult<()> {
        writeln!(
            out,
            "the vault daemon is running (version {})",
            self.client.daemon_version()
        )?;
        let status = self.status()?;
        let sandbox = if status.sandboxed {
            "yes (no network access)"
        } else {
            "NO"
        };
        writeln!(out, "  sandbox: {sandbox}")?;
        if !status.vault_exists {
            writeln!(out, "  no vault file yet")?;
            return Ok(());
        }
        for state in &status.domains {
            let Some(domain) = from_proto(state.domain) else {
                continue;
            };
            let text = match (state.available, state.unlocked) {
                (false, _) => "not available",
                (true, true) => "unlocked",
                (true, false) => "locked",
            };
            writeln!(out, "  {:<8} {text}", format!("{}:", domain_name(domain)))?;
        }
        Ok(())
    }

    /// `daemon stop`.
    pub(crate) fn stop(&mut self) -> CliResult<()> {
        self.call(request::Body::Shutdown(proto::Shutdown {}))?;
        Ok(())
    }

    /// Runs one of the commands the daemon carries out.
    pub(crate) fn run(&mut self, command: Command, out: &mut impl Write) -> CliResult<()> {
        match command {
            Command::Unlock { domain } => {
                let domain = DomainId::from(domain);
                self.ensure_unlocked(domain)?;
                writeln!(out, "unlocked: {}", domain_name(domain))?;
            }
            Command::Lock { domain } => {
                let domain = domain.map(DomainId::from);
                self.call(request::Body::Lock(proto::Lock {
                    domain: domain.map(|domain| to_proto(domain) as i32),
                }))?;
                match domain {
                    Some(domain) => writeln!(out, "locked: {}", domain_name(domain))?,
                    None => writeln!(out, "locked: all domains")?,
                }
            }
            Command::Add { kind } => {
                let id = self.add(kind)?;
                writeln!(out, "added {}", hex(&id))?;
            }
            Command::Get { id, reveal, copy } => {
                let request = request::Body::GetItem(proto::GetItem {
                    item_id: parse_id(&id)?.as_bytes().to_vec(),
                });
                let response::Body::Item(item) = self.call_unlocking(&request)? else {
                    return Err(unexpected());
                };
                if copy {
                    match &item.content {
                        Some(item::Content::Login(login)) => {
                            clipboard::copy(&login.password, "password", out)?;
                        }
                        Some(item::Content::Note(note)) => {
                            clipboard::copy(&note.body, "note text", out)?;
                        }
                        _ => {
                            return Err(
                                "only the password of a login or the text of a note can be copied"
                                    .into(),
                            );
                        }
                    }
                } else {
                    print_item(out, &item, reveal)?;
                }
            }
            Command::List { domain } => {
                let domain = DomainId::from(domain);
                self.ensure_unlocked(domain)?;
                let request = request::Body::ListItems(proto::ListItems {
                    domain: to_proto(domain) as i32,
                    query: String::new(),
                });
                let response::Body::Items(items) = self.call_unlocking(&request)? else {
                    return Err(unexpected());
                };
                for item in &items.items {
                    writeln!(
                        out,
                        "{}  {:<10}  {}",
                        hex(&item.item_id),
                        kind_name(item.kind),
                        item.title
                    )?;
                }
                writeln!(out, "{} item(s)", items.items.len())?;
            }
            Command::Totp { id, copy } => {
                let request = request::Body::TotpCode(proto::TotpCode {
                    item_id: parse_id(&id)?.as_bytes().to_vec(),
                });
                let response::Body::TotpCode(code) = self.call_unlocking(&request)? else {
                    return Err(unexpected());
                };
                if copy {
                    clipboard::copy(&code.code, "code", out)?;
                } else {
                    writeln!(out, "{} (valid for {}s)", code.code, code.seconds_remaining)?;
                }
            }
            Command::Delete { id } => {
                let id = parse_id(&id)?;
                let request = request::Body::DeleteItem(proto::DeleteItem {
                    item_id: id.as_bytes().to_vec(),
                });
                self.call_unlocking(&request)?;
                writeln!(out, "deleted {id}")?;
            }
            Command::RecoveryKit { replace } => self.recovery_kit(replace, out)?,
            Command::Devices => {
                let devices = self.devices()?;
                for device in &devices {
                    let state = match proto::DeviceState::try_from(device.state) {
                        Ok(proto::DeviceState::Revoked) => "revoked",
                        Ok(proto::DeviceState::ThisDevice) => "this device",
                        _ => "active",
                    };
                    writeln!(
                        out,
                        "{}  {:<11}  {} change(s) held  {}",
                        hex(&device.device_id),
                        state,
                        device.changes_held,
                        device.name
                    )?;
                }
                writeln!(out, "{} device(s)", devices.len())?;
            }
            Command::Revoke { device } => self.revoke(&device, out)?,
            Command::Passwd => {
                let current = self.input.secret("Current master password: ")?;
                let new = self.input.new_master_password()?;
                self.call(request::Body::ChangeMasterPassword(
                    proto::ChangeMasterPassword {
                        current: current.as_str().to_owned(),
                        new: new.as_str().to_owned(),
                    },
                ))?;
                writeln!(out, "master password changed")?;
            }
            Command::Pair | Command::Sync { .. } => {
                unreachable!("pairing and sync do not go through the daemon yet")
            }
        }
        Ok(())
    }

    fn add(&mut self, kind: AddKind) -> CliResult<Vec<u8>> {
        // Unlock first, then ask for the item's secret: the same order as the
        // prompts of every other command.
        let content = match kind {
            AddKind::Login {
                title,
                username,
                url,
            } => {
                self.ensure_unlocked(DomainId::Password)?;
                let password = self.input.secret("Password of the new login: ")?;
                new_item::Content::Login(proto::Login {
                    title,
                    username,
                    password: password.as_str().to_owned(),
                    urls: url,
                    notes: String::new(),
                })
            }
            AddKind::Note { title } => {
                self.ensure_unlocked(DomainId::Password)?;
                let body = self.input.secret("Note text: ")?;
                new_item::Content::Note(proto::Note {
                    title,
                    body: body.as_str().to_owned(),
                })
            }
            AddKind::Totp { login } => {
                let login = login.as_deref().map(parse_id).transpose()?;
                self.ensure_unlocked(DomainId::Totp)?;
                let uri = self.input.secret("otpauth:// URI: ")?;
                new_item::Content::Totp(proto::NewTotp {
                    otpauth_uri: uri.as_str().to_owned(),
                    login_id: login.map(|login| login.as_bytes().to_vec()),
                })
            }
        };
        let request = request::Body::AddItem(proto::AddItem {
            item: Some(proto::NewItem {
                content: Some(content),
            }),
        });
        match self.call_unlocking(&request)? {
            response::Body::ItemAdded(added) => Ok(added.item_id),
            _ => Err(unexpected()),
        }
    }

    fn recovery_kit(&mut self, replace: bool, out: &mut impl Write) -> CliResult<()> {
        if self.vault_status()?.has_recovery_kit && !replace {
            return Err("a recovery kit already exists; pass --replace to create a new one and invalidate the old recovery key".into());
        }
        self.unlock_every_domain()?;
        let request = request::Body::CreateRecoveryKit(proto::CreateRecoveryKit { replace });
        let response::Body::RecoveryKit(kit) = self.call_unlocking(&request)? else {
            return Err(unexpected());
        };
        writeln!(
            out,
            "Recovery key (write it down and keep it offline; it is shown only once):"
        )?;
        writeln!(out)?;
        writeln!(out, "    {}", kit.recovery_key)?;
        writeln!(out)?;
        writeln!(
            out,
            "To recover you need this key AND a backup copy of the vault file."
        )?;
        Ok(())
    }

    fn devices(&mut self) -> CliResult<Vec<proto::Device>> {
        match self.call(request::Body::ListDevices(proto::ListDevices {}))? {
            response::Body::Devices(devices) => Ok(devices.devices),
            _ => Err(unexpected()),
        }
    }

    fn revoke(&mut self, device: &str, out: &mut impl Write) -> CliResult<()> {
        let devices = self.devices()?;
        let prefix = device.trim().to_ascii_lowercase();
        let mut matches = devices
            .iter()
            .filter(|device| !prefix.is_empty() && hex(&device.device_id).starts_with(&prefix));
        let device = match (matches.next(), matches.next()) {
            (Some(device), None) => device,
            (None, _) => return Err("no device has that identifier; see `devices`".into()),
            _ => return Err("more than one device matches; give more of the identifier".into()),
        };
        match proto::DeviceState::try_from(device.state) {
            Ok(proto::DeviceState::ThisDevice) => {
                return Err("this device cannot revoke itself; do it from another device".into());
            }
            Ok(proto::DeviceState::Revoked) => {
                return Err("that device has already been revoked".into());
            }
            _ => {}
        }
        let id = hex(&device.device_id);
        // Replacing the keys of a domain takes that domain.
        self.unlock_every_domain()?;
        let question = format!(
            "Revoke the device \"{}\" ({id})? This cannot be undone. [y/N] ",
            device.name
        );
        let confirmed = matches!(
            self.input.line(&question)?,
            Some(answer) if answer.trim().eq_ignore_ascii_case("y")
        );
        if !confirmed {
            return Err("nothing was changed".into());
        }
        // A domain may have locked itself while the question was open.
        let request = request::Body::RevokeDevice(proto::RevokeDevice {
            device_id: device.device_id.clone(),
        });
        self.call_unlocking(&request)?;
        writeln!(out, "revoked device \"{}\" ({id})", device.name)?;
        writeln!(
            out,
            "The vault keys were replaced. The other devices receive the new keys with their next sync."
        )?;
        writeln!(
            out,
            "What the revoked device already holds stays readable to it: change those passwords if it was stolen."
        )?;
        Ok(())
    }
}

/// The name a list shows for the kind of an item.
fn kind_name(kind: i32) -> &'static str {
    match proto::ItemKind::try_from(kind) {
        Ok(proto::ItemKind::Login) => "Login",
        Ok(proto::ItemKind::Note) => "SecureNote",
        Ok(proto::ItemKind::Totp) => "Totp",
        Ok(proto::ItemKind::Passkey) => "Passkey",
        _ => "Unknown",
    }
}

fn print_item(out: &mut impl Write, item: &proto::Item, reveal: bool) -> io::Result<()> {
    match &item.content {
        Some(item::Content::Login(login)) => {
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
        Some(item::Content::Note(note)) => {
            writeln!(out, "kind:  note")?;
            writeln!(out, "title: {}", note.title)?;
            writeln!(out, "text:  {}", mask(&note.body, reveal))?;
        }
        Some(item::Content::Totp(entry)) => {
            writeln!(out, "kind:    totp")?;
            writeln!(out, "issuer:  {}", entry.issuer)?;
            writeln!(out, "account: {}", entry.account)?;
            writeln!(out, "digits:  {}", entry.digits)?;
            writeln!(out, "period:  {}s", entry.period)?;
            if let Some(login) = &entry.login_id {
                writeln!(out, "login:   {}", hex(login))?;
            }
        }
        Some(item::Content::Passkey(passkey)) => {
            writeln!(out, "kind:  passkey")?;
            writeln!(out, "rp_id: {}", passkey.rp_id)?;
            writeln!(out, "user:  {}", passkey.user_name)?;
        }
        None => writeln!(out, "kind:  unknown")?,
    }
    Ok(())
}

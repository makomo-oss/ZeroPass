//! The Linux sandbox (`docs/spec/ipc.md` §9.2): seccomp denies the sockets
//! that reach a network, Landlock limits the files to the system's libraries
//! and what was granted.
//!
//! Linux has no container a parent can start a process in the way Windows
//! starts one in an AppContainer. The sandboxed program restricts itself
//! instead, first thing, before it reads anything from outside: [`spawn`]
//! passes it the grants in an environment variable, and [`enter_requested`]
//! applies them. The restrictions are kept across `fork` and `exec`, so the
//! program's own child processes are sandboxed too.

use std::collections::BTreeMap;
use std::io;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};

use landlock::{
    ABI, Access as _, AccessFs, BitFlags, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus,
};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule,
};

use crate::Access;

/// The environment variable that carries the grants to the started program.
const ENV: &str = "ZEROPASS_SANDBOX";

/// The grants of each sandbox, in this process, until a program is started in it.
static GRANTS: Mutex<BTreeMap<String, Vec<(PathBuf, Access)>>> = Mutex::new(BTreeMap::new());

/// Whether this process restricted itself.
static ENTERED: AtomicBool = AtomicBool::new(false);

/// System paths, to read (and run: the kernel opens the dynamic loader as an
/// executable when a program starts its own workers): the loader and the
/// libraries, their configuration, and `/proc` (a process's own status, and
/// the executables of IPC peers). Nothing there is written.
const SYSTEM: [&str; 5] = ["/usr", "/lib", "/lib64", "/etc", "/proc"];

fn grants() -> MutexGuard<'static, BTreeMap<String, Vec<(PathBuf, Access)>>> {
    GRANTS.lock().unwrap_or_else(|poison| poison.into_inner())
}

fn code(access: Access) -> char {
    match access {
        Access::ReadExecute => 'x',
        Access::Modify => 'm',
        Access::CreateFiles => 'c',
    }
}

pub(crate) fn allow(container: &str, path: &Path, access: Access) -> io::Result<()> {
    if path.to_string_lossy().contains('\n') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a path with a line break cannot be granted",
        ));
    }
    let mut grants = grants();
    let list = grants.entry(container.to_owned()).or_default();
    if !list.iter().any(|(p, a)| p == path && *a == access) {
        list.push((path.to_path_buf(), access));
    }
    Ok(())
}

/// A started program.
#[derive(Debug)]
pub(crate) struct Child(Mutex<std::process::Child>);

impl Child {
    fn child(&self) -> MutexGuard<'_, std::process::Child> {
        self.0.lock().unwrap_or_else(|poison| poison.into_inner())
    }

    pub(crate) fn id(&self) -> u32 {
        self.child().id()
    }

    pub(crate) fn wait(&self) -> io::Result<u32> {
        let status = self.child().wait()?;
        Ok(status.code().map_or(u32::MAX, |code| code as u32))
    }

    pub(crate) fn try_wait(&self) -> io::Result<Option<u32>> {
        Ok(self
            .child()
            .try_wait()?
            .map(|status| status.code().map_or(u32::MAX, |code| code as u32)))
    }

    pub(crate) fn kill(&self) -> io::Result<()> {
        self.child().kill()
    }
}

pub(crate) fn spawn(
    container: &str,
    program: &Path,
    args: &[std::ffi::OsString],
) -> io::Result<Child> {
    let spec: String = grants()
        .get(container)
        .into_iter()
        .flatten()
        .map(|(path, access)| format!("{} {}\n", code(*access), path.display()))
        .collect();
    let child = Command::new(program)
        .args(args)
        .env(ENV, spec)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        // Not reached by the signals of this process's terminal.
        .process_group(0)
        .spawn()?;
    Ok(Child(Mutex::new(child)))
}

fn decode(spec: &str) -> io::Result<Vec<(PathBuf, Access)>> {
    spec.lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            let (kind, path) = line.split_once(' ').ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "malformed sandbox grant")
            })?;
            let access = match kind {
                "x" => Access::ReadExecute,
                "m" => Access::Modify,
                "c" => Access::CreateFiles,
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "unknown sandbox grant",
                    ));
                }
            };
            Ok((PathBuf::from(path), access))
        })
        .collect()
}

fn other(error: impl core::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}

/// Denies the sockets of every family but `AF_UNIX`, and `io_uring`, which
/// could make them without the `socket` call.
fn deny_network() -> io::Result<()> {
    let arch = std::env::consts::ARCH.try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "no seccomp filter for this architecture",
        )
    })?;
    let not_unix = SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Ne,
            libc::AF_UNIX as u64,
        )
        .map_err(other)?,
    ])
    .map_err(other)?;
    let rules = [
        (libc::SYS_socket, vec![not_unix]),
        (libc::SYS_io_uring_setup, vec![]),
    ]
    .into_iter()
    .collect();
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EACCES as u32),
        arch,
    )
    .map_err(other)?;
    let program: BpfProgram = filter.try_into().map_err(other)?;
    seccompiler::apply_filter_all_threads(&program).map_err(other)
}

/// Limits the files to the system's and the granted ones. Returns whether the
/// kernel enforces it (Landlock exists since Linux 5.13).
fn restrict_files(grants: &[(PathBuf, Access)]) -> io::Result<bool> {
    let abi = ABI::V3;
    let all = AccessFs::from_all(abi);
    let file_rights = AccessFs::from_file(abi);
    let read = AccessFs::from_read(abi);
    let mut rules = Vec::new();
    let mut add = |path: &Path, rights: BitFlags<AccessFs>| {
        // Not on this system (`/lib64` on some), or gone: nothing to allow.
        if let Ok(fd) = PathFd::new(path) {
            let rights = if path.is_dir() {
                rights
            } else {
                rights & file_rights
            };
            rules.push(PathBeneath::new(fd, rights));
        }
    };
    for path in SYSTEM {
        add(Path::new(path), read);
    }
    add(
        Path::new("/dev/null"),
        AccessFs::ReadFile | AccessFs::WriteFile,
    );
    for (path, access) in grants {
        let rights = match access {
            Access::ReadExecute => AccessFs::ReadFile | AccessFs::Execute,
            Access::Modify => AccessFs::ReadFile | AccessFs::WriteFile | AccessFs::Truncate,
            // A directory: everything beneath it. Landlock cannot tell the
            // files this process makes from the others there.
            Access::CreateFiles => all,
        };
        add(path, rights);
    }
    let status = Ruleset::default()
        .handle_access(all)
        .map_err(other)?
        .create()
        .map_err(other)?
        .add_rules(rules.into_iter().map(Ok::<_, landlock::RulesetError>))
        .map_err(other)?
        .restrict_self()
        .map_err(other)?;
    Ok(status.ruleset != RulesetStatus::NotEnforced)
}

/// What [`crate::enter_requested`] did.
pub(crate) fn enter_requested(extra: &[(&Path, Access)]) -> io::Result<Option<bool>> {
    let Some(spec) = std::env::var_os(ENV) else {
        return Ok(None);
    };
    let mut grants = decode(&spec.to_string_lossy())?;
    grants.extend(
        extra
            .iter()
            .map(|(path, access)| (path.to_path_buf(), *access)),
    );
    // Files first: the network filter does not keep Landlock from being set up.
    let files = restrict_files(&grants)?;
    deny_network()?;
    ENTERED.store(true, Ordering::SeqCst);
    Ok(Some(files))
}

/// Whether this process runs restricted: it restricted itself, or it was
/// started by one that had (a worker of the vault daemon).
pub(crate) fn is_sandboxed() -> bool {
    if ENTERED.load(Ordering::SeqCst) {
        return true;
    }
    std::env::var_os(ENV).is_some()
        && std::fs::read_to_string("/proc/self/status").is_ok_and(|status| {
            status
                .lines()
                .any(|line| line.starts_with("Seccomp:") && line.trim_end().ends_with('2'))
        })
}

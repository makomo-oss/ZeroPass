//! What a process that holds secrets does to itself at start-up
//! (`docs/spec/hardening.md`).
//!
//! The sandbox limits what the process can reach; these measures limit what
//! can reach into the process: no crash dump of its memory, no other program
//! of the user reading its memory or attaching a debugger, no DLL planted
//! beside it.

use std::io;

/// One measure and how applying it went.
#[derive(Debug)]
pub struct Measure {
    /// A short name for logs, such as `"no crash dumps"`.
    pub name: &'static str,
    /// Whether the measure is in effect.
    pub result: io::Result<()>,
}

/// What [`harden_process`] did.
#[derive(Debug, Default)]
pub struct Hardening {
    /// Every measure this platform has, in the order it was applied.
    pub measures: Vec<Measure>,
}

impl Hardening {
    fn apply(&mut self, name: &'static str, result: io::Result<()>) {
        self.measures.push(Measure { name, result });
    }

    /// The names of the measures in effect.
    pub fn applied(&self) -> Vec<&'static str> {
        self.measures
            .iter()
            .filter(|measure| measure.result.is_ok())
            .map(|measure| measure.name)
            .collect()
    }

    /// The measures that could not be applied, with the reason.
    pub fn failed(&self) -> Vec<String> {
        self.measures
            .iter()
            .filter_map(|measure| {
                let error = measure.result.as_ref().err()?;
                Some(format!("{} ({error})", measure.name))
            })
            .collect()
    }
}

/// Applies every hardening measure of this platform to the current process.
/// Call it first thing, before any secret is in memory. A measure that fails
/// does not stop the others; the caller decides what a failure means.
pub fn harden_process() -> Hardening {
    let mut hardening = Hardening::default();
    #[cfg(windows)]
    {
        use crate::windows_harden as os;
        hardening.apply(
            "DLLs from the system directory only",
            os::fix_dll_search_path(),
        );
        hardening.apply("no crash dumps", os::disable_crash_dumps());
        hardening.apply(
            "no access to memory by other programs",
            os::protect_memory(),
        );
        hardening.apply("no extension points", os::disable_extension_points());
        hardening.apply("no remote images", os::restrict_image_loads());
        hardening.apply("no dynamic code", os::prohibit_dynamic_code());
    }
    #[cfg(unix)]
    {
        use rustix::process::{Resource, Rlimit, setrlimit};
        let none = Rlimit {
            current: Some(0),
            maximum: Some(0),
        };
        hardening.apply(
            "no core dumps",
            setrlimit(Resource::Core, none).map_err(io::Error::from),
        );
    }
    // Linux: making the process non-dumpable (`PR_SET_DUMPABLE`) would keep
    // other programs of the user from reading its memory, but it also hides
    // `/proc/<pid>/exe`, by which the two ends of the local IPC check each
    // other. Both are settled together with the Linux sandbox (P6-10).
    hardening
}

/// Whether this process is allowed to read the memory of the process `pid`.
/// `None` where this platform offers no way to tell without trying to attach.
///
/// For tests and diagnostics: it shows whether [`harden_process`] took effect
/// in another process.
pub fn can_read_memory_of(pid: u32) -> Option<bool> {
    #[cfg(windows)]
    {
        Some(crate::windows_harden::can_read_memory_of(pid))
    }
    #[cfg(not(windows))]
    {
        let _ = pid;
        None
    }
}

/// Whether this process runs with the full rights of an administrator. Such a
/// process is outside what [`harden_process`] defends against: it can open
/// any process of the machine.
pub fn runs_as_administrator() -> bool {
    #[cfg(windows)]
    {
        crate::windows_harden::is_elevated()
    }
    #[cfg(unix)]
    {
        rustix::process::geteuid().is_root()
    }
}

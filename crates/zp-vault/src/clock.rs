//! Time sources and the hybrid logical clock that stamps item versions.

use core::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// A source of wall-clock time in milliseconds since the Unix epoch.
///
/// Injectable so that tests can control time; production code uses
/// [`Clock::system`].
#[derive(Clone)]
pub struct Clock(Arc<dyn Fn() -> u64 + Send + Sync>);

impl Clock {
    /// The operating system clock.
    pub fn system() -> Self {
        Self::from_fn(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| {
                    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
                })
        })
    }

    /// A clock backed by an arbitrary function.
    pub fn from_fn(now_ms: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        Self(Arc::new(now_ms))
    }

    /// The current time in milliseconds since the Unix epoch.
    pub fn now_ms(&self) -> u64 {
        (self.0)()
    }
}

impl fmt::Debug for Clock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Clock")
    }
}

/// Number of low bits of an HLC stamp used for the logical counter.
const COUNTER_BITS: u32 = 16;
/// Largest stamp that still fits the database's signed 64-bit integer column.
const MAX_STAMP: u64 = i64::MAX as u64;

/// A hybrid logical clock: `stamp = unix_ms << 16 | counter`
/// (`docs/spec/crypto.md` §1).
///
/// Stamps are strictly increasing even if the wall clock stalls or jumps back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Hlc {
    last: u64,
}

impl Hlc {
    /// Resumes after the newest stamp already present in the vault.
    pub(crate) const fn resume_after(last: u64) -> Self {
        Self { last }
    }

    /// Returns a stamp greater than every stamp issued or observed so far, or
    /// `None` if the clock is exhausted (not before the year 6429).
    pub(crate) fn tick(&mut self, now_ms: u64) -> Option<u64> {
        let physical = now_ms
            .checked_shl(COUNTER_BITS)
            .filter(|p| p >> COUNTER_BITS == now_ms);
        let next = match physical {
            Some(physical) if physical > self.last => physical,
            _ => self.last.checked_add(1)?,
        };
        if next > MAX_STAMP {
            return None;
        }
        self.last = next;
        Some(next)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    #[test]
    fn stamps_follow_the_wall_clock() {
        let mut hlc = Hlc::resume_after(0);
        assert_eq!(hlc.tick(1_000), Some(1_000 << 16));
        assert_eq!(hlc.tick(1_001), Some(1_001 << 16));
    }

    #[test]
    fn same_millisecond_increments_the_counter() {
        let mut hlc = Hlc::resume_after(0);
        assert_eq!(hlc.tick(5), Some(5 << 16));
        assert_eq!(hlc.tick(5), Some((5 << 16) + 1));
        assert_eq!(hlc.tick(5), Some((5 << 16) + 2));
    }

    #[test]
    fn stamps_never_go_backwards() {
        let mut hlc = Hlc::resume_after(0);
        let first = hlc.tick(10_000).unwrap();
        let second = hlc.tick(3).unwrap();
        assert_eq!(second, first + 1);
        // Once the wall clock catches up it takes over again.
        assert_eq!(hlc.tick(10_001), Some(10_001 << 16));
    }

    #[test]
    fn resumes_after_stamps_already_in_the_vault() {
        let existing = (9_000 << 16) + 7;
        let mut hlc = Hlc::resume_after(existing);
        assert_eq!(hlc.tick(8_000), Some(existing + 1));
    }

    #[test]
    fn exhaustion_is_reported_instead_of_wrapping() {
        let mut hlc = Hlc::resume_after(MAX_STAMP);
        assert_eq!(hlc.tick(1), None);
        let mut hlc = Hlc::resume_after(0);
        assert_eq!(
            hlc.tick(u64::MAX),
            Some(1),
            "an absurd wall clock falls back to last + 1"
        );
    }

    #[test]
    fn clocks_can_be_injected() {
        let now = Arc::new(AtomicU64::new(42));
        let source = Arc::clone(&now);
        let clock = Clock::from_fn(move || source.load(Ordering::SeqCst));
        assert_eq!(clock.now_ms(), 42);
        now.store(43, Ordering::SeqCst);
        assert_eq!(clock.clone().now_ms(), 43);
        assert!(Clock::system().now_ms() > 1_700_000_000_000);
    }
}

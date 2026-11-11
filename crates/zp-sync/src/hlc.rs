//! The hybrid logical clock that stamps item versions (`docs/spec/sync.md` §3).
//!
//! ```text
//! stamp = unix_ms(48 bits) << 16 | counter(16 bits)
//! ```
//!
//! Stamps order versions across devices. They follow the wall clock when it
//! behaves, and stay strictly increasing when it stalls, jumps back, or lags
//! behind stamps received from other devices.

/// Number of low bits of a stamp used for the logical counter.
pub const COUNTER_BITS: u32 = 16;
/// Largest valid stamp: stamps must fit a signed 64-bit integer.
pub const MAX_STAMP: u64 = i64::MAX as u64;
/// How far into the future (by the local clock) a received stamp may lie before
/// it is refused: 24 hours.
pub const MAX_CLOCK_SKEW_MS: u64 = 24 * 60 * 60 * 1000;

/// The wall-clock part of a stamp, in milliseconds since the Unix epoch.
pub const fn physical_ms(stamp: u64) -> u64 {
    stamp >> COUNTER_BITS
}

/// Whether a stamp received from another device is acceptable at local time
/// `now_ms`: valid, and not further than [`MAX_CLOCK_SKEW_MS`] in the future.
///
/// Without this guard a single device with a wildly wrong clock would drag every
/// other device's clock forward for good.
pub const fn is_acceptable(stamp: u64, now_ms: u64) -> bool {
    stamp <= MAX_STAMP && physical_ms(stamp) <= now_ms.saturating_add(MAX_CLOCK_SKEW_MS)
}

/// A hybrid logical clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hlc {
    last: u64,
}

impl Hlc {
    /// Resumes after the newest stamp already known (0 for a fresh clock).
    pub const fn resume_after(last: u64) -> Self {
        Self { last }
    }

    /// The newest stamp issued or observed so far.
    pub const fn last(&self) -> u64 {
        self.last
    }

    /// Issues a stamp greater than every stamp issued or observed so far, or
    /// `None` if the clock is exhausted (not before the year 6429).
    pub fn tick(&mut self, now_ms: u64) -> Option<u64> {
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

    /// Records a stamp received from another device, so that later local stamps
    /// order after it. Callers check [`is_acceptable`] first.
    pub fn observe(&mut self, stamp: u64) {
        self.last = self.last.max(stamp);
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn stamps_follow_the_wall_clock() {
        let mut hlc = Hlc::resume_after(0);
        assert_eq!(hlc.tick(1_000), Some(1_000 << 16));
        assert_eq!(hlc.tick(1_001), Some(1_001 << 16));
        assert_eq!(physical_ms(hlc.last()), 1_001);
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
        assert_eq!(hlc.tick(3), Some(first + 1));
        // Once the wall clock catches up it takes over again.
        assert_eq!(hlc.tick(10_001), Some(10_001 << 16));
    }

    #[test]
    fn observed_stamps_push_the_clock_forward_only() {
        let mut hlc = Hlc::resume_after(0);
        hlc.tick(1_000).unwrap();
        let remote = (5_000 << 16) + 9;
        hlc.observe(remote);
        assert_eq!(hlc.tick(1_001), Some(remote + 1));
        hlc.observe(7);
        assert_eq!(hlc.last(), remote + 1);
    }

    #[test]
    fn exhaustion_is_reported_instead_of_wrapping() {
        assert_eq!(Hlc::resume_after(MAX_STAMP).tick(1), None);
        assert_eq!(
            Hlc::resume_after(0).tick(u64::MAX),
            Some(1),
            "an absurd wall clock falls back to last + 1"
        );
    }

    #[test]
    fn far_future_and_invalid_stamps_are_not_acceptable() {
        let now = 1_800_000_000_000u64;
        assert!(is_acceptable(now << 16, now));
        assert!(is_acceptable(0, now));
        assert!(is_acceptable(
            ((now + MAX_CLOCK_SKEW_MS) << 16) | 0xFFFF,
            now
        ));
        assert!(!is_acceptable((now + MAX_CLOCK_SKEW_MS + 1) << 16, now));
        assert!(!is_acceptable(MAX_STAMP + 1, u64::MAX));
        assert!(is_acceptable(MAX_STAMP, u64::MAX));
    }

    #[derive(Debug, Clone)]
    enum Event {
        Tick(u64),
        Observe(u64),
    }

    fn event() -> impl Strategy<Value = Event> {
        prop_oneof![
            (0u64..4_000_000_000_000).prop_map(Event::Tick),
            (0u64..=MAX_STAMP / 2).prop_map(Event::Observe),
        ]
    }

    proptest! {
        /// Whatever the wall clock and the other devices do, every issued stamp is
        /// greater than all stamps issued or observed before it.
        #[test]
        fn issued_stamps_are_strictly_increasing(events in proptest::collection::vec(event(), 1..200)) {
            let mut hlc = Hlc::resume_after(0);
            let mut highest_seen = 0u64;
            for event in events {
                match event {
                    Event::Tick(now_ms) => {
                        let stamp = hlc.tick(now_ms).unwrap();
                        prop_assert!(stamp > highest_seen);
                        // A stamp never lags behind the wall clock.
                        prop_assert!(physical_ms(stamp) >= now_ms);
                        highest_seen = stamp;
                    }
                    Event::Observe(stamp) => {
                        hlc.observe(stamp);
                        highest_seen = highest_seen.max(stamp);
                    }
                }
                prop_assert_eq!(hlc.last(), highest_seen);
            }
        }

        /// With a well-behaved wall clock and no remote stamps, stamps track it.
        #[test]
        fn stamps_track_an_increasing_wall_clock(mut times in proptest::collection::vec(1u64..4_000_000_000_000, 1..100)) {
            times.sort_unstable();
            times.dedup();
            let mut hlc = Hlc::resume_after(0);
            for now_ms in times {
                prop_assert_eq!(hlc.tick(now_ms), Some(now_ms << COUNTER_BITS));
            }
        }
    }
}

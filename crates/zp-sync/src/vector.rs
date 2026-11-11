//! Version vectors (`docs/spec/sync.md` §4).
//!
//! For each device, a version vector records up to which sequence number that
//! device's ops are held: an entry `n` for device X means "ops 1..=n authored by X
//! are all present". Devices exchange vectors to work out which ops the other
//! side is missing.

use core::cmp::Ordering;
use std::collections::BTreeMap;

use zp_crypto::DeviceId;

/// A version vector. Devices without an entry are at sequence number 0.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VersionVector(BTreeMap<DeviceId, u64>);

impl VersionVector {
    /// The empty vector: nothing is held from anyone.
    pub fn new() -> Self {
        Self::default()
    }

    /// The highest contiguous sequence number held from `device` (0 if none).
    pub fn get(&self, device: &DeviceId) -> u64 {
        self.0.get(device).copied().unwrap_or(0)
    }

    /// Raises the entry of `device` to `seq`. Entries never decrease; a lower
    /// value is ignored.
    pub fn advance(&mut self, device: DeviceId, seq: u64) {
        if seq > self.get(&device) {
            self.0.insert(device, seq);
        }
    }

    /// The entries in device order. Zero entries are never stored.
    pub fn iter(&self) -> impl Iterator<Item = (DeviceId, u64)> + '_ {
        self.0.iter().map(|(device, seq)| (*device, *seq))
    }

    /// Number of devices with a non-zero entry.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether nothing is held from anyone.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Takes the per-device maximum of both vectors.
    pub fn merge(&mut self, other: &Self) {
        for (device, seq) in other.iter() {
            self.advance(device, seq);
        }
    }

    /// Whether everything described by `other` is also held here.
    pub fn includes(&self, other: &Self) -> bool {
        other.iter().all(|(device, seq)| self.get(&device) >= seq)
    }

    /// For each device from which `self` holds more than `other`, the range of
    /// sequence numbers `other` is missing, as `(device, after, up_to)`: the ops
    /// with `after < seq <= up_to`.
    pub fn ahead_of(&self, other: &Self) -> Vec<(DeviceId, u64, u64)> {
        self.iter()
            .filter_map(|(device, mine)| {
                let theirs = other.get(&device);
                (mine > theirs).then_some((device, theirs, mine))
            })
            .collect()
    }
}

impl FromIterator<(DeviceId, u64)> for VersionVector {
    fn from_iter<I: IntoIterator<Item = (DeviceId, u64)>>(entries: I) -> Self {
        let mut vector = Self::new();
        for (device, seq) in entries {
            vector.advance(device, seq);
        }
        vector
    }
}

/// The causal order: `a <= b` when `b` includes everything in `a`. Vectors that
/// each hold something the other lacks are concurrent (`None`).
impl PartialOrd for VersionVector {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (other.includes(self), self.includes(other)) {
            (true, true) => Some(Ordering::Equal),
            (true, false) => Some(Ordering::Less),
            (false, true) => Some(Ordering::Greater),
            (false, false) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn device(n: u8) -> DeviceId {
        DeviceId::from_bytes([n; 16])
    }

    fn vector(entries: &[(u8, u64)]) -> VersionVector {
        entries.iter().map(|&(n, seq)| (device(n), seq)).collect()
    }

    #[test]
    fn missing_devices_are_at_zero_and_zero_is_not_stored() {
        let mut v = VersionVector::new();
        assert!(v.is_empty());
        assert_eq!(v.get(&device(1)), 0);
        v.advance(device(1), 0);
        assert!(v.is_empty());
        assert_eq!(v, vector(&[(1, 0)]));
    }

    #[test]
    fn entries_only_ever_increase() {
        let mut v = vector(&[(1, 5)]);
        v.advance(device(1), 3);
        assert_eq!(v.get(&device(1)), 5);
        v.advance(device(1), 8);
        assert_eq!(v.get(&device(1)), 8);
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn comparison_distinguishes_before_after_equal_and_concurrent() {
        let a = vector(&[(1, 2), (2, 1)]);
        let b = vector(&[(1, 3), (2, 1)]);
        let c = vector(&[(1, 2), (2, 4)]);
        assert_eq!(a.partial_cmp(&b), Some(Ordering::Less));
        assert_eq!(b.partial_cmp(&a), Some(Ordering::Greater));
        assert_eq!(a.partial_cmp(&a.clone()), Some(Ordering::Equal));
        assert_eq!(b.partial_cmp(&c), None);
        assert!(VersionVector::new() < a);
    }

    #[test]
    fn merge_takes_the_per_device_maximum() {
        let mut a = vector(&[(1, 2), (2, 7)]);
        a.merge(&vector(&[(1, 5), (3, 1)]));
        assert_eq!(a, vector(&[(1, 5), (2, 7), (3, 1)]));
    }

    #[test]
    fn ahead_of_lists_exactly_the_missing_ranges() {
        let mine = vector(&[(1, 5), (2, 3), (3, 9)]);
        let theirs = vector(&[(1, 5), (2, 1), (4, 2)]);
        assert_eq!(
            mine.ahead_of(&theirs),
            [(device(2), 1, 3), (device(3), 0, 9)]
        );
        assert_eq!(theirs.ahead_of(&mine), [(device(4), 0, 2)]);
        assert!(mine.ahead_of(&mine).is_empty());
    }

    fn any_vector() -> impl Strategy<Value = VersionVector> {
        proptest::collection::vec((0u8..6, 0u64..20), 0..8).prop_map(|entries| vector(&entries))
    }

    fn merged(a: &VersionVector, b: &VersionVector) -> VersionVector {
        let mut out = a.clone();
        out.merge(b);
        out
    }

    proptest! {
        #[test]
        fn merge_is_commutative_associative_and_idempotent(
            a in any_vector(), b in any_vector(), c in any_vector(),
        ) {
            prop_assert_eq!(merged(&a, &b), merged(&b, &a));
            prop_assert_eq!(merged(&merged(&a, &b), &c), merged(&a, &merged(&b, &c)));
            prop_assert_eq!(merged(&a, &a), a.clone());
            prop_assert_eq!(merged(&a, &VersionVector::new()), a);
        }

        #[test]
        fn merge_is_the_least_upper_bound(a in any_vector(), b in any_vector(), c in any_vector()) {
            let m = merged(&a, &b);
            prop_assert!(m.includes(&a) && m.includes(&b));
            // Any vector that includes both also includes their merge.
            if c.includes(&a) && c.includes(&b) {
                prop_assert!(c.includes(&m));
            }
        }

        #[test]
        fn comparison_is_a_partial_order(a in any_vector(), b in any_vector(), c in any_vector()) {
            // Reflexive.
            prop_assert_eq!(a.partial_cmp(&a), Some(Ordering::Equal));
            // Antisymmetric: mutual inclusion means equality.
            if a <= b && b <= a {
                prop_assert_eq!(&a, &b);
            }
            // Transitive.
            if a <= b && b <= c {
                prop_assert!(a <= c);
            }
            // Consistent with the reverse comparison.
            prop_assert_eq!(a.partial_cmp(&b), b.partial_cmp(&a).map(Ordering::reverse));
        }

        #[test]
        fn sending_what_is_ahead_makes_the_receiver_catch_up(a in any_vector(), b in any_vector()) {
            // After `b` receives every range `a` is ahead by, `b` includes `a`.
            let mut caught_up = b.clone();
            for (device, after, up_to) in a.ahead_of(&b) {
                prop_assert_eq!(after, b.get(&device));
                prop_assert!(up_to > after);
                caught_up.advance(device, up_to);
            }
            prop_assert!(caught_up.includes(&a));
            prop_assert_eq!(caught_up, merged(&a, &b));
        }
    }
}

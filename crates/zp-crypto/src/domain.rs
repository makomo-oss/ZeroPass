//! Key domains: the three independently keyed compartments of a vault.

mod sealed {
    pub trait Sealed {}
}

/// Runtime identifier of a key domain, as stored on disk and bound into AAD.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum DomainId {
    /// Logins and secure notes; unlocked with the master password.
    Password = 0x01,
    /// TOTP seeds; unlocked only through a biometric-gated hardware key.
    Totp = 0x02,
    /// Passkey private keys; unlocked only through a biometric-gated hardware key.
    Passkey = 0x03,
}

impl DomainId {
    /// All domains, in identifier order.
    pub const ALL: [DomainId; 3] = [DomainId::Password, DomainId::Totp, DomainId::Passkey];

    /// The one-byte on-disk representation.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parses the on-disk representation.
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(DomainId::Password),
            0x02 => Some(DomainId::Totp),
            0x03 => Some(DomainId::Passkey),
            _ => None,
        }
    }
}

/// Compile-time marker for a key domain.
///
/// Keys are parameterised by their domain so that, for example, a password-domain
/// key cannot be passed where a TOTP-domain key is required. The trait is sealed:
/// the set of domains is fixed by the specification.
pub trait Domain: sealed::Sealed + 'static {
    /// The runtime identifier of this domain.
    const ID: DomainId;
}

/// Marker for the password domain (logins and notes).
#[derive(Debug)]
pub enum Password {}
/// Marker for the TOTP domain.
#[derive(Debug)]
pub enum Totp {}
/// Marker for the passkey domain.
#[derive(Debug)]
pub enum Passkey {}

impl sealed::Sealed for Password {}
impl sealed::Sealed for Totp {}
impl sealed::Sealed for Passkey {}

impl Domain for Password {
    const ID: DomainId = DomainId::Password;
}
impl Domain for Totp {
    const ID: DomainId = DomainId::Totp;
}
impl Domain for Passkey {
    const ID: DomainId = DomainId::Passkey;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_round_trips() {
        for id in DomainId::ALL {
            assert_eq!(DomainId::from_u8(id.as_u8()), Some(id));
        }
        assert_eq!(DomainId::from_u8(0), None);
        assert_eq!(DomainId::from_u8(4), None);
    }

    #[test]
    fn markers_map_to_ids() {
        assert_eq!(Password::ID.as_u8(), 1);
        assert_eq!(Totp::ID.as_u8(), 2);
        assert_eq!(Passkey::ID.as_u8(), 3);
    }
}

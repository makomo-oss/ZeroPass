//! Key derivation: Argon2id for the master password and HKDF-SHA256 for labels
//! (`docs/spec/crypto.md` §5).
//!
//! ```text
//! pw    = UTF-8(NFKC(master password))
//! ikm   = Argon2id(pw, kdf_salt, m, t, p, 32 bytes)
//! KEK-P = HKDF-SHA256(salt = kdf_salt, ikm, info = "zeropass/v1/kek/password")
//! ```

use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::secret::KEY_LEN;
use crate::{CryptoError, PasswordKek};

/// Length of the Argon2id salt.
pub const KDF_SALT_LEN: usize = 16;

const INFO_KEK_PASSWORD: &[u8] = b"zeropass/v1/kek/password";

/// Argon2id cost parameters, as stored in a password key slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    m_kib: u32,
    t: u32,
    p: u32,
}

impl KdfParams {
    /// The weakest parameters a new vault may be created with (OWASP minimum).
    pub const MINIMUM: Self = Self {
        m_kib: 19 * 1024,
        t: 2,
        p: 1,
    };
    /// The starting point of calibration: 64 MiB, 3 passes, 1 lane.
    pub const DEFAULT: Self = Self {
        m_kib: 64 * 1024,
        t: 3,
        p: 1,
    };

    /// Largest memory cost accepted when reading a vault: 1 GiB.
    pub const MAX_M_KIB: u32 = 1024 * 1024;
    /// Largest pass count accepted when reading a vault.
    pub const MAX_T: u32 = 64;
    /// Largest lane count accepted when reading a vault.
    pub const MAX_P: u32 = 16;
    /// Largest pass count calibration will choose.
    pub const MAX_CALIBRATED_T: u32 = 16;

    /// Validates parameters read from disk or chosen by a caller.
    ///
    /// Rejects values Argon2 cannot run with and values above the read-time
    /// ceilings, so a tampered vault file cannot make unlocking exhaust resources.
    /// This does not enforce the creation floor; see [`Self::meets_minimum`].
    pub fn new(m_kib: u32, t: u32, p: u32) -> Result<Self, CryptoError> {
        let valid = (1..=Self::MAX_P).contains(&p)
            && (1..=Self::MAX_T).contains(&t)
            && m_kib <= Self::MAX_M_KIB
            && m_kib >= 8 * p;
        if valid {
            Ok(Self { m_kib, t, p })
        } else {
            Err(CryptoError::InvalidKdfParams)
        }
    }

    /// Memory cost in KiB.
    pub const fn m_kib(&self) -> u32 {
        self.m_kib
    }

    /// Number of passes.
    pub const fn t(&self) -> u32 {
        self.t
    }

    /// Degree of parallelism (lanes).
    pub const fn p(&self) -> u32 {
        self.p
    }

    /// Whether the parameters are at least as strong as [`Self::MINIMUM`] in every
    /// dimension. New vaults must satisfy this.
    pub const fn meets_minimum(&self) -> bool {
        self.m_kib >= Self::MINIMUM.m_kib && self.t >= Self::MINIMUM.t && self.p >= Self::MINIMUM.p
    }

    /// Chooses parameters so that one derivation on this machine takes roughly
    /// `target`: memory and lanes stay at [`Self::DEFAULT`] and the pass count is
    /// raised, between the default and [`Self::MAX_CALIBRATED_T`].
    pub fn calibrate(target: Duration) -> Result<Self, CryptoError> {
        let mut failure = None;
        let params = Self::calibrate_with(target, |params| {
            let start = Instant::now();
            let mut out = Zeroizing::new([0u8; KEY_LEN]);
            if let Err(e) = argon2id(params, b"calibration", &[0u8; KDF_SALT_LEN], &mut out) {
                failure = Some(e);
            }
            start.elapsed()
        });
        failure.map_or(Ok(params), Err)
    }

    fn calibrate_with(target: Duration, measure: impl FnOnce(&Self) -> Duration) -> Self {
        let base = Self::DEFAULT;
        let per_pass = measure(&base).as_secs_f64() / f64::from(base.t);
        let wanted = if per_pass > 0.0 {
            (target.as_secs_f64() / per_pass).ceil()
        } else {
            0.0
        };
        // `as` saturates for out-of-range floats, and the clamp bounds the result.
        let t = (wanted as u32).clamp(base.t, Self::MAX_CALIBRATED_T);
        Self { t, ..base }
    }
}

fn argon2id(
    params: &KdfParams,
    password: &[u8],
    salt: &[u8],
    out: &mut [u8; KEY_LEN],
) -> Result<(), CryptoError> {
    let params = Params::new(params.m_kib, params.t, params.p, Some(KEY_LEN))
        .map_err(|_| CryptoError::InvalidKdfParams)?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password, salt, out)
        .map_err(|_| CryptoError::Kdf)
}

/// HKDF-SHA256 extract-and-expand into a 32-byte key.
pub(crate) fn hkdf_sha256(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<(), CryptoError> {
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, out)
        .map_err(|_| CryptoError::Kdf)
}

/// Derives `KEK-P`, the key that wraps the password-domain vault key, from the
/// master password.
///
/// The result is typed for the password domain only: it cannot wrap or unwrap the
/// TOTP or passkey vault keys.
pub fn derive_password_kek(
    master_password: &str,
    salt: &[u8; KDF_SALT_LEN],
    params: &KdfParams,
) -> Result<PasswordKek, CryptoError> {
    let normalized = Zeroizing::new(master_password.nfkc().collect::<String>());
    let mut ikm = Zeroizing::new([0u8; KEY_LEN]);
    argon2id(params, normalized.as_bytes(), salt, &mut ikm)?;
    PasswordKek::from_fn(|out| hkdf_sha256(salt, ikm.as_slice(), INFO_KEK_PASSWORD, out))
}

#[cfg(test)]
mod tests {
    use subtle::ConstantTimeEq;

    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 9106 §5.3: Argon2id with secret and associated data.
    #[test]
    fn argon2id_matches_rfc_9106() {
        let params = argon2::ParamsBuilder::new()
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .data(argon2::AssociatedData::new(&[0x04; 12]).unwrap())
            .output_len(32)
            .build()
            .unwrap();
        let argon =
            Argon2::new_with_secret(&[0x03; 8], Algorithm::Argon2id, Version::V0x13, params)
                .unwrap();
        let mut tag = [0u8; 32];
        argon
            .hash_password_into(&[0x01; 32], &[0x02; 16], &mut tag)
            .unwrap();
        assert_eq!(
            tag.to_vec(),
            hex("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
        );
    }

    /// RFC 5869 appendix A.1.
    #[test]
    fn hkdf_matches_rfc_5869() {
        let mut okm = [0u8; 42];
        hkdf_sha256(
            &hex("000102030405060708090a0b0c"),
            &[0x0b; 22],
            &hex("f0f1f2f3f4f5f6f7f8f9"),
            &mut okm,
        )
        .unwrap();
        assert_eq!(
            okm.to_vec(),
            hex(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf
                 34007208d5b887185865"
            )
        );
    }

    const FAST: KdfParams = KdfParams {
        m_kib: 64,
        t: 1,
        p: 1,
    };
    const SALT: [u8; KDF_SALT_LEN] = [0x5A; KDF_SALT_LEN];

    fn same(a: &PasswordKek, b: &PasswordKek) -> bool {
        a.ct_eq(b).into()
    }

    /// Pins the composition (NFKC → Argon2id → HKDF with the spec's label). The
    /// expected value was produced by this implementation; the primitives are
    /// checked against the RFC vectors above.
    #[test]
    fn password_kek_is_stable() {
        let kek = derive_password_kek("correct horse battery staple", &SALT, &FAST).unwrap();

        let mut ikm = [0u8; 32];
        argon2id(&FAST, b"correct horse battery staple", &SALT, &mut ikm).unwrap();
        let mut expected = [0u8; 32];
        hkdf_sha256(&SALT, &ikm, b"zeropass/v1/kek/password", &mut expected).unwrap();
        assert_eq!(kek.expose(), &expected);
        assert_ne!(
            kek.expose(),
            &ikm,
            "the Argon2 output must not be used directly"
        );
    }

    #[test]
    fn password_kek_depends_on_password_salt_and_params() {
        let base = derive_password_kek("password one", &SALT, &FAST).unwrap();
        assert!(same(
            &base,
            &derive_password_kek("password one", &SALT, &FAST).unwrap()
        ));

        let other_pw = derive_password_kek("password two", &SALT, &FAST).unwrap();
        let other_salt = derive_password_kek("password one", &[0x5B; 16], &FAST).unwrap();
        let other_params =
            derive_password_kek("password one", &SALT, &KdfParams { t: 2, ..FAST }).unwrap();
        assert!(!same(&base, &other_pw));
        assert!(!same(&base, &other_salt));
        assert!(!same(&base, &other_params));
    }

    #[test]
    fn password_is_nfkc_normalised() {
        // Full-width "ｐａｓｓ１" and a decomposed "é" normalise to their composed forms.
        let a = derive_password_kek("ｐａｓｓ１ cafe\u{0301}", &SALT, &FAST).unwrap();
        let b = derive_password_kek("pass1 caf\u{00e9}", &SALT, &FAST).unwrap();
        assert!(same(&a, &b));
    }

    #[test]
    fn params_are_validated() {
        assert!(KdfParams::new(19 * 1024, 2, 1).is_ok());
        assert!(KdfParams::new(KdfParams::MAX_M_KIB, KdfParams::MAX_T, KdfParams::MAX_P).is_ok());
        for (m, t, p) in [
            (0, 1, 1),
            (7, 1, 1),
            (64, 0, 1),
            (64, 1, 0),
            (KdfParams::MAX_M_KIB + 1, 1, 1),
            (64, KdfParams::MAX_T + 1, 1),
            (1024, 1, KdfParams::MAX_P + 1),
            (u32::MAX, u32::MAX, u32::MAX),
        ] {
            assert_eq!(
                KdfParams::new(m, t, p).unwrap_err(),
                CryptoError::InvalidKdfParams
            );
        }
    }

    #[test]
    fn minimum_is_checked_in_every_dimension() {
        assert!(KdfParams::MINIMUM.meets_minimum());
        assert!(KdfParams::DEFAULT.meets_minimum());
        assert!(!FAST.meets_minimum());
        assert!(
            !KdfParams {
                t: 1,
                ..KdfParams::MINIMUM
            }
            .meets_minimum()
        );
        assert!(
            !KdfParams {
                m_kib: 19 * 1024 - 1,
                ..KdfParams::MINIMUM
            }
            .meets_minimum()
        );
    }

    #[test]
    fn calibration_scales_passes_towards_the_target() {
        let target = Duration::from_millis(500);
        let run = |elapsed_ms| {
            KdfParams::calibrate_with(target, |p| {
                assert_eq!(*p, KdfParams::DEFAULT);
                Duration::from_millis(elapsed_ms)
            })
        };
        // 3 passes took 150 ms → 50 ms per pass → 10 passes.
        assert_eq!(
            run(150),
            KdfParams {
                t: 10,
                ..KdfParams::DEFAULT
            }
        );
        // A slow machine never goes below the default.
        assert_eq!(run(2_000), KdfParams::DEFAULT);
        // A very fast machine is capped.
        assert_eq!(run(1).t(), KdfParams::MAX_CALIBRATED_T);
        assert_eq!(run(0).t(), KdfParams::DEFAULT.t());
        assert!(run(150).meets_minimum());
    }

    #[test]
    fn calibration_runs_for_real() {
        let params = KdfParams::calibrate(Duration::from_millis(1)).unwrap();
        assert_eq!(params, KdfParams::DEFAULT);
    }
}

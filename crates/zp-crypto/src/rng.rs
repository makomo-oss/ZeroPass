//! Random bytes from the operating system CSPRNG. No userspace generator is used.

use crate::CryptoError;

/// Fills `dest` with cryptographically secure random bytes.
pub fn fill(dest: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::fill(dest).map_err(|_| CryptoError::Rng)
}

/// Returns `N` cryptographically secure random bytes.
pub fn array<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut out = [0u8; N];
    fill(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn produces_distinct_output() {
        let a: [u8; 32] = array().unwrap();
        let b: [u8; 32] = array().unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }
}

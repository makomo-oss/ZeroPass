//! The password generator. Random characters from the operating system's
//! random number generator, drawn without bias.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!#$%&()*+,-./:;<=>?@[]^_{|}~";
/// Characters that are easily mistaken for one another when read or typed.
const AMBIGUOUS: &str = "Il1O0o|`'\"";

/// The shortest and longest password the generator makes.
pub(crate) const MIN_LENGTH: u32 = 8;
pub(crate) const MAX_LENGTH: u32 = 128;

/// What the user chose.
#[derive(Debug, Clone, Copy, Deserialize)]
pub(crate) struct Options {
    pub(crate) length: u32,
    pub(crate) lowercase: bool,
    pub(crate) uppercase: bool,
    pub(crate) digits: bool,
    pub(crate) symbols: bool,
    pub(crate) avoid_ambiguous: bool,
}

/// A generated password and how hard it is to guess.
#[derive(Serialize)]
pub(crate) struct Generated {
    pub(crate) password: String,
    /// log2 of the number of passwords the options allow (an upper bound
    /// on the entropy).
    pub(crate) bits: f64,
}

/// What can go wrong.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum GeneratorError {
    /// No kind of character was chosen.
    NoCharacters,
    /// The length is outside [`MIN_LENGTH`]..=[`MAX_LENGTH`].
    BadLength,
    /// The operating system did not provide randomness.
    Random,
}

impl std::fmt::Display for GeneratorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GeneratorError::NoCharacters => f.write_str("choose at least one kind of character"),
            GeneratorError::BadLength => write!(
                f,
                "the length must be between {MIN_LENGTH} and {MAX_LENGTH}"
            ),
            GeneratorError::Random => f.write_str("the system's random number generator failed"),
        }
    }
}

fn class(chars: &str, avoid_ambiguous: bool) -> Vec<char> {
    chars
        .chars()
        .filter(|c| !avoid_ambiguous || !AMBIGUOUS.contains(*c))
        .collect()
}

/// A uniformly random index below `bound` (which is small), by rejection
/// sampling: never biased towards the start of the alphabet.
fn random_below(bound: usize) -> Result<usize, GeneratorError> {
    let bound = u32::try_from(bound).map_err(|_| GeneratorError::NoCharacters)?;
    if bound == 0 {
        return Err(GeneratorError::NoCharacters);
    }
    // The largest multiple of `bound` that fits: values at or above it are
    // drawn again.
    let limit = u32::MAX - (u32::MAX % bound);
    loop {
        let mut bytes = [0u8; 4];
        getrandom::fill(&mut bytes).map_err(|_| GeneratorError::Random)?;
        let value = u32::from_le_bytes(bytes);
        if value < limit {
            return Ok((value % bound) as usize);
        }
    }
}

/// Makes a password. Every chosen kind of character appears at least once.
pub(crate) fn generate(options: Options) -> Result<Generated, GeneratorError> {
    if !(MIN_LENGTH..=MAX_LENGTH).contains(&options.length) {
        return Err(GeneratorError::BadLength);
    }
    let classes: Vec<Vec<char>> = [
        (options.lowercase, LOWER),
        (options.uppercase, UPPER),
        (options.digits, DIGITS),
        (options.symbols, SYMBOLS),
    ]
    .into_iter()
    .filter(|(chosen, _)| *chosen)
    .map(|(_, chars)| class(chars, options.avoid_ambiguous))
    .collect();
    if classes.is_empty() {
        return Err(GeneratorError::NoCharacters);
    }
    let alphabet: Vec<char> = classes.iter().flatten().copied().collect();
    let length = options.length as usize;
    // Drawn again until every class is present: with the minimum length of
    // 8 and at most 4 classes this ends after a few tries, and the result is
    // uniform among the passwords that contain every class.
    loop {
        let mut password = Zeroizing::new(String::with_capacity(length));
        for _ in 0..length {
            let index = random_below(alphabet.len())?;
            password.push(alphabet[index]);
        }
        if classes
            .iter()
            .all(|class| password.chars().any(|c| class.contains(&c)))
        {
            let bits = length as f64 * (alphabet.len() as f64).log2();
            return Ok(Generated {
                password: password.as_str().to_owned(),
                bits,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(length: u32) -> Options {
        Options {
            length,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: false,
        }
    }

    #[test]
    fn passwords_have_the_length_and_every_chosen_kind() {
        for _ in 0..200 {
            let generated = generate(options(12)).unwrap();
            let password = &generated.password;
            assert_eq!(password.chars().count(), 12);
            assert!(password.chars().any(|c| c.is_ascii_lowercase()));
            assert!(password.chars().any(|c| c.is_ascii_uppercase()));
            assert!(password.chars().any(|c| c.is_ascii_digit()));
            assert!(password.chars().any(|c| SYMBOLS.contains(c)));
        }
    }

    #[test]
    fn only_chosen_kinds_appear() {
        let generated = generate(Options {
            length: 64,
            lowercase: false,
            uppercase: false,
            digits: true,
            symbols: false,
            avoid_ambiguous: true,
        })
        .unwrap();
        assert!(generated.password.chars().all(|c| c.is_ascii_digit()));
        assert!(!generated.password.contains(['0', '1']));
        // 8 digits remain: 3 bits each.
        assert!((generated.bits - 64.0 * 3.0).abs() < 1e-9);
    }

    #[test]
    fn bad_options_are_refused() {
        let none = Options {
            length: 20,
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            avoid_ambiguous: false,
        };
        assert_eq!(generate(none).err(), Some(GeneratorError::NoCharacters));
        assert_eq!(
            generate(options(MIN_LENGTH - 1)).err(),
            Some(GeneratorError::BadLength)
        );
        assert_eq!(
            generate(options(MAX_LENGTH + 1)).err(),
            Some(GeneratorError::BadLength)
        );
    }

    #[test]
    fn characters_are_spread_evenly() {
        // 10 digits, 20 000 draws: each should come up about 2 000 times.
        let mut counts = [0u32; 10];
        for _ in 0..20_000 {
            counts[random_below(10).unwrap()] += 1;
        }
        for count in counts {
            assert!((1_700..=2_300).contains(&count), "{counts:?}");
        }
    }

    #[test]
    fn two_passwords_differ() {
        let a = generate(options(32)).unwrap().password;
        let b = generate(options(32)).unwrap().password;
        assert_ne!(a, b);
    }
}

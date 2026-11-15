//! The way to the platform's hardware key store (`docs/spec/ipc.md` §13).
//!
//! No process of the vault daemon touches the hardware key store itself: the
//! daemon runs in a sandbox, and Windows Hello keeps the credentials of a
//! sandbox apart from the user's own (ADR-0006). A key agent outside the
//! sandbox signs instead. The process that needs the signature seals a reply
//! key into its request, so the processes in between carry only ciphertext.

use std::sync::Arc;

use zeroize::Zeroizing;
use zp_crypto::{
    HardwareKeyError, HardwareKeyStore, SealingKey, SignatureKeyStore, UserVerifyingSigner,
};
use zp_ipc::proto::{self, KeyStoreProblem, key_agent_reply::Outcome, key_agent_request::Ask};

/// Carries a question to the key agent and its answer back.
pub(crate) trait KeyAgentPort: Send + Sync {
    /// Asks the key agent. Never fails: what went wrong is an [`Outcome`].
    fn ask(&self, ask: Ask) -> Outcome;
}

pub(crate) fn failed(problem: KeyStoreProblem, message: impl Into<String>) -> Outcome {
    Outcome::Failed(proto::KeyStoreFailure {
        problem: problem as i32,
        message: message.into(),
    })
}

fn failure(failure: &proto::KeyStoreFailure) -> HardwareKeyError {
    match KeyStoreProblem::try_from(failure.problem) {
        Ok(KeyStoreProblem::Unavailable) => HardwareKeyError::Unavailable(failure.message.clone()),
        Ok(KeyStoreProblem::UserCancelled) => HardwareKeyError::UserCancelled,
        _ => HardwareKeyError::Platform(failure.message.clone()),
    }
}

/// What the key agent says to a question it was not asked.
fn unexpected() -> HardwareKeyError {
    HardwareKeyError::Platform("the key agent gave an answer to another question".into())
}

/// Signs through the key agent.
struct AgentSigner {
    port: Arc<dyn KeyAgentPort>,
}

impl UserVerifyingSigner for AgentSigner {
    fn sign(&self, challenge: &[u8]) -> Result<Zeroizing<Vec<u8>>, HardwareKeyError> {
        let platform =
            |error: zp_crypto::CryptoError| HardwareKeyError::Platform(error.to_string());
        // For this one signature: what the agent sends back opens only here.
        let reply_key = SealingKey::generate().map_err(platform)?;
        let ask = Ask::Sign(proto::KeyAgentSign {
            challenge: challenge.to_vec(),
            reply_key: reply_key.public_bytes().to_vec(),
        });
        match self.port.ask(ask) {
            Outcome::Signature(sealed) => reply_key.open(challenge, &sealed).map_err(|_| {
                HardwareKeyError::Platform("the key agent's answer could not be opened".into())
            }),
            Outcome::Failed(why) => Err(failure(&why)),
            Outcome::Available(_) => Err(unexpected()),
        }
    }
}

/// The platform's hardware key store, reached through the key agent. `Ok(Err)`
/// says why this device has none. With `create`, the store's key is created if
/// it is missing, which may ask the user.
pub(crate) fn key_store(
    port: &Arc<dyn KeyAgentPort>,
    create: bool,
) -> Result<Result<Box<dyn HardwareKeyStore>, String>, HardwareKeyError> {
    match port.ask(Ask::Probe(proto::KeyAgentProbe { create })) {
        Outcome::Available(store) => {
            let id = u8::try_from(store.implementation_id).map_err(|_| unexpected())?;
            let signer = AgentSigner {
                port: Arc::clone(port),
            };
            Ok(Ok(Box::new(SignatureKeyStore::new(signer, id))))
        }
        Outcome::Failed(why) => match failure(&why) {
            HardwareKeyError::Unavailable(reason) => Ok(Err(reason)),
            other => Err(other),
        },
        Outcome::Signature(_) => Err(unexpected()),
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    use zp_crypto::seal_to;

    use super::*;

    /// A key agent with a deterministic stand-in for the hardware: signs with
    /// a fixed secret, like a hardware key that never leaves the device.
    pub(crate) struct FakeAgent {
        secret: [u8; 32],
        pub(crate) available: AtomicBool,
        pub(crate) user_present: AtomicBool,
        pub(crate) prompts: AtomicU32,
        /// Every signature it gave, as the hardware returned it.
        pub(crate) signatures: Mutex<Vec<Vec<u8>>>,
    }

    impl FakeAgent {
        pub(crate) fn new(secret: u8) -> Self {
            Self {
                secret: [secret; 32],
                available: AtomicBool::new(true),
                user_present: AtomicBool::new(true),
                prompts: AtomicU32::new(0),
                signatures: Mutex::new(Vec::new()),
            }
        }

        fn signature(&self, challenge: &[u8]) -> Vec<u8> {
            // Deterministic, as the real store's signatures must be.
            let mut out = Vec::with_capacity(64);
            for round in 0u8..2 {
                let mut state = self.secret;
                for (index, byte) in challenge.iter().enumerate() {
                    let slot = (index + usize::from(round) * 7) % 32;
                    state[slot] = state[slot].wrapping_mul(31).wrapping_add(*byte ^ round);
                }
                out.extend_from_slice(&state);
            }
            out
        }
    }

    impl KeyAgentPort for FakeAgent {
        fn ask(&self, ask: Ask) -> Outcome {
            if !self.available.load(Ordering::SeqCst) {
                return failed(KeyStoreProblem::Unavailable, "the test has no key store");
            }
            match ask {
                Ask::Probe(_) => Outcome::Available(proto::KeyStoreAvailable {
                    implementation_id: 0x7E,
                }),
                Ask::Sign(sign) => {
                    self.prompts.fetch_add(1, Ordering::SeqCst);
                    if !self.user_present.load(Ordering::SeqCst) {
                        return failed(KeyStoreProblem::UserCancelled, "cancelled");
                    }
                    let Ok(reply_key) = <[u8; 32]>::try_from(sign.reply_key.as_slice()) else {
                        return failed(KeyStoreProblem::Platform, "bad reply key");
                    };
                    let signature = self.signature(&sign.challenge);
                    self.signatures
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner())
                        .push(signature.clone());
                    match seal_to(&reply_key, &sign.challenge, &signature) {
                        Ok(sealed) => Outcome::Signature(sealed),
                        Err(error) => failed(KeyStoreProblem::Platform, error.to_string()),
                    }
                }
            }
        }
    }

    #[test]
    fn a_key_wrapped_through_the_agent_unwraps_only_with_the_user() {
        use zp_crypto::{Totp, VaultId, VaultKey};

        let agent = Arc::new(FakeAgent::new(7));
        let port: Arc<dyn KeyAgentPort> = agent.clone();
        let store = key_store(&port, true).unwrap().unwrap();
        let vault = VaultId::from_bytes([1; 16]);
        let key = VaultKey::<Totp>::generate().unwrap();
        let slot = key.wrap_with_hardware(store.as_ref(), &vault).unwrap();
        assert_eq!(slot[0], 0x7E);
        let back = VaultKey::<Totp>::unwrap_with_hardware(store.as_ref(), &vault, &slot).unwrap();
        assert_eq!(*back.to_transfer_bytes(), *key.to_transfer_bytes());
        assert_eq!(agent.prompts.load(Ordering::SeqCst), 2);

        agent.user_present.store(false, Ordering::SeqCst);
        assert_eq!(
            VaultKey::<Totp>::unwrap_with_hardware(store.as_ref(), &vault, &slot).unwrap_err(),
            zp_crypto::CryptoError::HardwareKey(HardwareKeyError::UserCancelled)
        );

        // Another device's hardware opens nothing.
        let other: Arc<dyn KeyAgentPort> = Arc::new(FakeAgent::new(8));
        let other = key_store(&other, false).unwrap().unwrap();
        assert!(VaultKey::<Totp>::unwrap_with_hardware(other.as_ref(), &vault, &slot).is_err());
    }

    #[test]
    fn a_device_without_a_key_store_is_told_apart_from_a_failure() {
        let agent = Arc::new(FakeAgent::new(7));
        agent.available.store(false, Ordering::SeqCst);
        let port: Arc<dyn KeyAgentPort> = agent;
        assert_eq!(
            key_store(&port, true).unwrap().err().unwrap(),
            "the test has no key store"
        );
    }
}

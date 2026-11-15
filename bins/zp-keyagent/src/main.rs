//! ZeroPass key agent (`docs/spec/ipc.md` §13).
//!
//! The vault daemon runs in a sandbox, and the platform's hardware key store
//! keeps what a sandbox creates apart from the user's own keys (ADR-0006).
//! This small program runs outside the sandbox, for as long as a user
//! interface needs it: it attaches to the vault daemon, and when the daemon
//! needs the hardware key store it asks here. The store verifies the user
//! (fingerprint, face or PIN) for every signature.
//!
//! The agent holds no vault key and opens no vault file. It seals each
//! signature to the process of the daemon that asked, so that nothing in
//! between can use it. It ends when its standard input closes: the user
//! interface that started it keeps the other end.

use std::error::Error;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::thread;

use clap::Parser;
use zp_crypto::{HardwareKeyError, PUBLIC_KEY_LEN, UserVerifyingSigner, seal_to};
use zp_ipc::proto::{
    self, KeyAgentReply, KeyStoreProblem, key_agent_reply::Outcome, key_agent_request::Ask,
    request, response,
};
use zp_ipc::{Client, DaemonPolicy, Endpoint};

#[derive(Parser)]
#[command(name = "zp-keyagent", version, about = "ZeroPass key agent")]
struct Args {
    /// Path of the vault file whose daemon to attach to.
    #[arg(long, env = "ZEROPASS_VAULT")]
    vault: PathBuf,
}

/// The length of the challenges the vault signs to wrap a key
/// (`docs/spec/crypto.md` §7). Nothing else is signed here.
const CHALLENGE_LEN: usize = 32;

/// Exit code after an internal error (a panic).
const EXIT_PANIC: i32 = 101;

fn log(message: &str) {
    let _ = writeln!(io::stderr(), "zp-keyagent: {message}");
}

fn failed(id: u64, error: &HardwareKeyError) -> KeyAgentReply {
    let problem = match error {
        HardwareKeyError::Unavailable(_) => KeyStoreProblem::Unavailable,
        HardwareKeyError::UserCancelled => KeyStoreProblem::UserCancelled,
        _ => KeyStoreProblem::Platform,
    };
    let message = match error {
        HardwareKeyError::Unavailable(reason) | HardwareKeyError::Platform(reason) => {
            reason.clone()
        }
        other => other.to_string(),
    };
    KeyAgentReply::failed(id, problem, message)
}

/// A hardware key store that is opened when it is first needed.
struct Store<S, O> {
    open: O,
    opened: Option<(S, u8)>,
}

impl<S, O> Store<S, O>
where
    S: UserVerifyingSigner,
    O: Fn(bool) -> Result<(S, u8), HardwareKeyError>,
{
    fn new(open: O) -> Self {
        Self { open, opened: None }
    }

    fn get(&mut self, create: bool) -> Result<&(S, u8), HardwareKeyError> {
        if self.opened.is_none() {
            self.opened = Some((self.open)(create)?);
        }
        self.opened
            .as_ref()
            .ok_or_else(|| HardwareKeyError::Platform("the key store did not open".into()))
    }

    /// Answers one question of the vault daemon.
    fn answer(&mut self, question: proto::KeyAgentRequest) -> KeyAgentReply {
        let id = question.id;
        let outcome = match question.ask {
            Some(Ask::Probe(probe)) => self.get(probe.create).map(|(_, implementation)| {
                Outcome::Available(proto::KeyStoreAvailable {
                    implementation_id: u32::from(*implementation),
                })
            }),
            Some(Ask::Sign(sign)) => self.sign(&sign),
            None => Err(HardwareKeyError::Platform(
                "a question this version does not know".into(),
            )),
        };
        match outcome {
            Ok(outcome) => KeyAgentReply {
                id,
                outcome: Some(outcome),
            },
            Err(error) => failed(id, &error),
        }
    }

    fn sign(&mut self, sign: &proto::KeyAgentSign) -> Result<Outcome, HardwareKeyError> {
        let malformed = |what: &str| HardwareKeyError::Platform(what.to_owned());
        if sign.challenge.len() != CHALLENGE_LEN {
            return Err(malformed("only key-wrapping challenges are signed"));
        }
        let reply_key: [u8; PUBLIC_KEY_LEN] = sign
            .reply_key
            .as_slice()
            .try_into()
            .map_err(|_| malformed("the reply key is malformed"))?;
        let (signer, _) = self.get(false)?;
        // Shows the platform's prompt and waits for the user.
        let signature = signer.sign(&sign.challenge)?;
        let sealed = seal_to(&reply_key, &sign.challenge, &signature)
            .map_err(|error| HardwareKeyError::Platform(error.to_string()))?;
        Ok(Outcome::Signature(sealed))
    }
}

fn platform(create: bool) -> Result<(zp_hwkey::PlatformSigner, u8), HardwareKeyError> {
    let signer = zp_hwkey::platform_signer(create)?;
    let implementation = signer.implementation_id();
    Ok((signer, implementation))
}

fn run(args: &Args) -> Result<(), Box<dyn Error>> {
    let endpoint = Endpoint::for_vault(&args.vault)?;
    // Only the vault daemon installed beside this program is answered.
    let policy = DaemonPolicy::beside_current_exe()?;
    let connect = || Client::connect(&endpoint, &policy, "zp-keyagent");
    let attach = request::Body::KeyAgentAttach(proto::KeyAgentAttach {});
    let (relay, mut downlink) = connect()?.start_relay(attach)?;
    let mut uplink = connect()?.attach_relay(relay)?;

    // Ends with the program that started it.
    thread::spawn(|| {
        let _ = io::stdin().read_to_end(&mut Vec::new());
        std::process::exit(0);
    });

    let mut store = Store::new(platform);
    loop {
        match downlink.receive() {
            Ok(response::Body::Listening(_)) => {
                // Tells the program that started it that the daemon can ask now.
                let mut stdout = io::stdout();
                writeln!(stdout, "ready")?;
                stdout.flush()?;
            }
            Ok(response::Body::KeyAgentRequest(question)) => {
                uplink.send(request::Body::KeyAgentReply(store.answer(question)))?;
            }
            // The daemon let go of the relay, or stopped.
            Ok(response::Body::Done(_)) | Err(_) => return Ok(()),
            Ok(_) => {}
        }
    }
}

fn main() -> ExitCode {
    // Before anything else: a signature that passes through here opens a
    // vault key.
    let hardening = zp_sandbox::harden_process();
    std::panic::set_hook(Box::new(|info| {
        log(&format!("internal error: {info}"));
        std::process::exit(EXIT_PANIC);
    }));
    let args = Args::parse();
    for failure in hardening.failed() {
        log(&format!("warning: could not apply: {failure}"));
    }
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            log(&format!("error: {error}"));
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use zeroize::Zeroizing;
    use zp_crypto::SealingKey;

    use super::*;

    struct FakeSigner<'a> {
        prompts: &'a Cell<u32>,
        user_present: bool,
    }

    impl UserVerifyingSigner for FakeSigner<'_> {
        fn sign(&self, challenge: &[u8]) -> Result<Zeroizing<Vec<u8>>, HardwareKeyError> {
            self.prompts.set(self.prompts.get() + 1);
            if !self.user_present {
                return Err(HardwareKeyError::UserCancelled);
            }
            let mut signature = challenge.to_vec();
            signature.reverse();
            Ok(Zeroizing::new(signature))
        }
    }

    fn probe(create: bool) -> proto::KeyAgentRequest {
        proto::KeyAgentRequest {
            id: 7,
            ask: Some(Ask::Probe(proto::KeyAgentProbe { create })),
        }
    }

    fn sign(challenge: &[u8], reply_key: &[u8]) -> proto::KeyAgentRequest {
        proto::KeyAgentRequest {
            id: 8,
            ask: Some(Ask::Sign(proto::KeyAgentSign {
                challenge: challenge.to_vec(),
                reply_key: reply_key.to_vec(),
            })),
        }
    }

    fn problem(reply: &KeyAgentReply) -> KeyStoreProblem {
        match &reply.outcome {
            Some(Outcome::Failed(failure)) => KeyStoreProblem::try_from(failure.problem).unwrap(),
            other => panic!("not a failure: {other:?}"),
        }
    }

    #[test]
    fn a_signature_is_sealed_to_the_process_that_asked() {
        let prompts = Cell::new(0);
        let opened = Cell::new(0);
        let mut store = Store::new(|_| {
            opened.set(opened.get() + 1);
            Ok((
                FakeSigner {
                    prompts: &prompts,
                    user_present: true,
                },
                0x42,
            ))
        });
        let reply = store.answer(probe(false));
        assert_eq!(reply.id, 7);
        assert_eq!(
            reply.outcome,
            Some(Outcome::Available(proto::KeyStoreAvailable {
                implementation_id: 0x42
            }))
        );
        // Asking whether there is a store asks the user nothing.
        assert_eq!(prompts.get(), 0);

        let challenge = [0xC4; CHALLENGE_LEN];
        let reply_key = SealingKey::generate().unwrap();
        let reply = store.answer(sign(&challenge, reply_key.public_bytes()));
        assert_eq!(reply.id, 8);
        let Some(Outcome::Signature(sealed)) = reply.outcome else {
            panic!("no signature");
        };
        assert_eq!(prompts.get(), 1);
        // Not the signature itself: only the holder of the reply key reads it.
        assert!(!sealed.windows(8).any(|window| window == [0xC4; 8]));
        let signature = reply_key.open(&challenge, &sealed).unwrap();
        assert_eq!(signature.as_slice(), [0xC4; CHALLENGE_LEN]);
        let other = SealingKey::generate().unwrap();
        assert!(other.open(&challenge, &sealed).is_err());
        // The store was opened once.
        assert_eq!(opened.get(), 1);
    }

    #[test]
    fn only_key_wrapping_challenges_are_signed() {
        let prompts = Cell::new(0);
        let mut store = Store::new(|_| {
            Ok((
                FakeSigner {
                    prompts: &prompts,
                    user_present: true,
                },
                1,
            ))
        });
        let reply_key = SealingKey::generate().unwrap();
        for challenge in [&[0u8; 31][..], &[0u8; 33], b"a message to sign", &[]] {
            let reply = store.answer(sign(challenge, reply_key.public_bytes()));
            assert_eq!(problem(&reply), KeyStoreProblem::Platform);
        }
        let reply = store.answer(sign(&[0; CHALLENGE_LEN], &[1, 2, 3]));
        assert_eq!(problem(&reply), KeyStoreProblem::Platform);
        let empty = proto::KeyAgentRequest { id: 9, ask: None };
        assert_eq!(problem(&store.answer(empty)), KeyStoreProblem::Platform);
        // The user was never asked.
        assert_eq!(prompts.get(), 0);
    }

    #[test]
    fn what_the_store_reports_is_passed_on() {
        let prompts = Cell::new(0);
        let mut absent = Store::new(|_| -> Result<(FakeSigner<'_>, u8), _> {
            Err(HardwareKeyError::Unavailable("not set up".into()))
        });
        let reply = absent.answer(probe(true));
        assert_eq!(problem(&reply), KeyStoreProblem::Unavailable);
        assert!(matches!(
            &reply.outcome,
            Some(Outcome::Failed(failure)) if failure.message == "not set up"
        ));
        // It is asked again the next time: the user may have set it up.
        assert_eq!(
            problem(&absent.answer(probe(true))),
            KeyStoreProblem::Unavailable
        );

        let mut declined = Store::new(|_| {
            Ok((
                FakeSigner {
                    prompts: &prompts,
                    user_present: false,
                },
                1,
            ))
        });
        let reply_key = SealingKey::generate().unwrap();
        let reply = declined.answer(sign(&[0; CHALLENGE_LEN], reply_key.public_bytes()));
        assert_eq!(problem(&reply), KeyStoreProblem::UserCancelled);
        assert_eq!(prompts.get(), 1);
    }

    #[test]
    fn command_line_is_well_formed() {
        use clap::CommandFactory;
        Args::command().debug_assert();
    }
}

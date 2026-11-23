//! The key agent, as the process the clients talk to sees it
//! (`docs/spec/ipc.md` §13).
//!
//! The agent connects like any client and keeps a relay open. Whatever
//! process of the daemon needs the hardware key store, its question goes down
//! that relay and the answer comes back up.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use zp_ipc::RelayEnd;
use zp_ipc::proto::{
    self, KeyStoreProblem, key_agent_reply::Outcome, key_agent_request::Ask, request, response,
};

use crate::port::{KeyAgentPort, failed};

/// How long the key agent has to answer: the user reads the prompt and
/// presents a finger or types a PIN.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(180);

/// One attached key agent.
struct Attached {
    generation: u64,
    to_agent: Mutex<Sender<response::Body>>,
    /// Locked for a whole question: one at a time.
    replies: Mutex<Receiver<proto::KeyAgentReply>>,
}

/// The key agent that is attached at the moment, if any.
#[derive(Default)]
pub(crate) struct AgentLink {
    attached: Mutex<Option<Arc<Attached>>>,
    generations: AtomicU64,
    questions: AtomicU64,
    /// Whether no agent means no key store rather than a failure.
    absent_is_unavailable: bool,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poison| poison.into_inner())
}

impl AgentLink {
    /// A link for a program whose key agent is optional: the Android app
    /// attaches one only if the device has a key store, so without one the
    /// store is unavailable rather than missing by mistake.
    pub(crate) fn optional() -> Self {
        Self {
            absent_is_unavailable: true,
            ..Self::default()
        }
    }

    /// Uses the key agent at the other end of `relay` until it goes away. A
    /// newer agent replaces an older one.
    pub(crate) fn attach(&self, relay: RelayEnd) -> response::Body {
        let RelayEnd { incoming, outgoing } = relay;
        let generation = self.generations.fetch_add(1, Ordering::SeqCst) + 1;
        let (replies_tx, replies_rx) = mpsc::channel();
        *lock(&self.attached) = Some(Arc::new(Attached {
            generation,
            to_agent: Mutex::new(outgoing.clone()),
            replies: Mutex::new(replies_rx),
        }));
        // From here on a client's request can reach the agent.
        if outgoing
            .send(response::Body::Listening(proto::Listening {}))
            .is_ok()
        {
            for message in incoming {
                if let request::Body::KeyAgentReply(reply) = message
                    && replies_tx.send(reply).is_err()
                {
                    break;
                }
            }
        }
        let mut attached = lock(&self.attached);
        if attached
            .as_ref()
            .is_some_and(|agent| agent.generation == generation)
        {
            *attached = None;
        }
        response::Body::Done(proto::Done {})
    }
}

impl KeyAgentPort for AgentLink {
    fn ask(&self, ask: Ask) -> Outcome {
        let Some(agent) = lock(&self.attached).clone() else {
            // On Windows the store is there and only the agent is missing: an
            // error, so that a vault is not created without the TOTP and
            // passkey domains by mistake. Elsewhere there is no store to ask
            // yet (`zp-hwkey`).
            let problem = if cfg!(windows) && !self.absent_is_unavailable {
                KeyStoreProblem::Platform
            } else {
                KeyStoreProblem::Unavailable
            };
            return failed(
                problem,
                "no key agent is attached (the client starts `zp-keyagent`)",
            );
        };
        let gone = || failed(KeyStoreProblem::Platform, "the key agent went away");
        let replies = lock(&agent.replies);
        let id = self.questions.fetch_add(1, Ordering::SeqCst) + 1;
        let question =
            response::Body::KeyAgentRequest(proto::KeyAgentRequest { id, ask: Some(ask) });
        if lock(&agent.to_agent).send(question).is_err() {
            return gone();
        }
        let deadline = Instant::now() + ANSWER_TIMEOUT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match replies.recv_timeout(left) {
                // An answer to a question that was given up on.
                Ok(reply) if reply.id != id => {}
                Ok(reply) => {
                    return reply.outcome.unwrap_or_else(|| {
                        failed(KeyStoreProblem::Platform, "the key agent gave no answer")
                    });
                }
                Err(RecvTimeoutError::Timeout) => {
                    return failed(
                        KeyStoreProblem::UserCancelled,
                        "the key agent did not answer in time",
                    );
                }
                Err(RecvTimeoutError::Disconnected) => return gone(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;
    use crate::port::testing::FakeAgent;

    /// Plays a key agent on a relay: answers `questions` questions with
    /// `fake` and goes away.
    pub(crate) fn play(
        fake: &FakeAgent,
        downlink: &Receiver<response::Body>,
        uplink: Sender<request::Body>,
        questions: usize,
    ) {
        for _ in 0..questions {
            let Ok(message) = downlink.recv() else { break };
            if let response::Body::KeyAgentRequest(question) = message {
                let Some(ask) = question.ask else { continue };
                let reply = proto::KeyAgentReply {
                    id: question.id,
                    outcome: Some(fake.ask(ask)),
                };
                if uplink.send(request::Body::KeyAgentReply(reply)).is_err() {
                    break;
                }
            }
        }
    }

    #[test]
    fn questions_reach_the_attached_agent_and_only_while_it_is_attached() {
        let link = Arc::new(AgentLink::default());
        let probe = || Ask::Probe(proto::KeyAgentProbe { create: false });
        assert!(matches!(link.ask(probe()), Outcome::Failed(_)));

        let (uplink, incoming) = mpsc::channel();
        let (outgoing, downlink) = mpsc::channel();
        let relay = {
            let link = Arc::clone(&link);
            thread::spawn(move || link.attach(RelayEnd { incoming, outgoing }))
        };
        // The daemon says when the agent can be asked.
        assert!(matches!(
            downlink.recv().unwrap(),
            response::Body::Listening(_)
        ));
        let agent = thread::spawn(move || play(&FakeAgent::new(3), &downlink, uplink, 2));
        assert!(matches!(link.ask(probe()), Outcome::Available(_)));
        assert!(matches!(link.ask(probe()), Outcome::Available(_)));

        // The agent has gone away: the relay ends, and there is nobody to ask.
        agent.join().unwrap();
        assert!(matches!(relay.join().unwrap(), response::Body::Done(_)));
        assert!(matches!(link.ask(probe()), Outcome::Failed(_)));
    }
}

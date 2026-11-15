//! What the processes of the vault daemon say to each other (ADR-0007).
//!
//! The process the clients talk to starts the others and talks to each over
//! that process's standard input and output, in the frames of the IPC
//! protocol. These messages never leave the daemon: they may change with any
//! version, and both ends are always the same executable.

use prost::{Message, Oneof};
use zp_ipc::proto;

/// Nothing to say beyond the kind of the message.
#[derive(Clone, Copy, PartialEq, Message)]
pub(crate) struct Empty {}

/// A vault key on its way to the process that will hold it.
#[derive(Clone, PartialEq, Message)]
pub(crate) struct KeyTransfer {
    #[prost(enumeration = "proto::Domain", tag = "1")]
    pub(crate) domain: i32,
    /// The generation of the key.
    #[prost(uint32, tag = "2")]
    pub(crate) epoch: u32,
    /// The slot key, sealed to the receiving process (`zp_crypto::seal_to`).
    #[prost(bytes = "vec", tag = "3")]
    pub(crate) sealed: Vec<u8>,
}

/// Asks a process to hand an unlocked domain to another one.
#[derive(Clone, PartialEq, Message)]
pub(crate) struct ExportKey {
    #[prost(enumeration = "proto::Domain", tag = "1")]
    pub(crate) domain: i32,
    /// The public key of the receiving process.
    #[prost(bytes = "vec", tag = "2")]
    pub(crate) to: Vec<u8>,
}

/// The public key to seal a vault key to.
#[derive(Clone, PartialEq, Message)]
pub(crate) struct ImportKey {
    #[prost(bytes = "vec", tag = "1")]
    pub(crate) key: Vec<u8>,
}

/// From the process the clients talk to, to one it started.
#[derive(Clone, PartialEq, Message)]
pub(crate) struct Down {
    #[prost(oneof = "down::Body", tags = "1, 2, 3, 4, 5, 6, 7, 8, 9")]
    pub(crate) body: Option<down::Body>,
}

pub(crate) mod down {
    use super::{Empty, ExportKey, KeyTransfer, Oneof, proto};

    #[derive(Clone, PartialEq, Oneof)]
    pub(crate) enum Body {
        /// A client's request to answer. Answered by `Reply`.
        #[prost(message, tag = "1")]
        Call(proto::Request),
        /// A client's request that starts a relay. Answered by `RelayData`
        /// messages and, at the end, `Reply`.
        #[prost(message, tag = "2")]
        Relay(proto::Request),
        /// What the client sent on the uplink of the relay.
        #[prost(message, tag = "3")]
        RelayData(proto::Request),
        /// The client closed the uplink of the relay.
        #[prost(message, tag = "4")]
        RelayClosed(Empty),
        /// The key agent's answer to an `AgentRequest`.
        #[prost(message, tag = "5")]
        AgentReply(proto::KeyAgentReply),
        /// Asks for the key to seal a vault key to. Answered by `ImportKey`.
        #[prost(message, tag = "6")]
        ImportKey(Empty),
        /// Unlocks a domain with a key another process sealed. Answered by
        /// `Reply`.
        #[prost(message, tag = "7")]
        Import(KeyTransfer),
        /// Asks for an unlocked domain, sealed. Answered by `Exported`, or by
        /// `Reply` with the error.
        #[prost(message, tag = "8")]
        Export(ExportKey),
        /// The vault file was replaced: forget what is open. Answered by `Reply`.
        #[prost(message, tag = "9")]
        Reset(Empty),
    }
}

/// From a started process back to the one the clients talk to.
#[derive(Clone, PartialEq, Message)]
pub(crate) struct Up {
    #[prost(oneof = "up::Body", tags = "1, 2, 3, 4, 5")]
    pub(crate) body: Option<up::Body>,
}

pub(crate) mod up {
    use super::{ImportKey, KeyTransfer, Oneof, proto};

    #[derive(Clone, PartialEq, Oneof)]
    pub(crate) enum Body {
        /// The answer to the client's request, or the outcome of an order.
        #[prost(message, tag = "1")]
        Reply(proto::Response),
        /// A message for the client on the downlink of the relay.
        #[prost(message, tag = "2")]
        RelayData(proto::Response),
        /// Something to ask the key agent. Answered by `AgentReply`.
        #[prost(message, tag = "3")]
        AgentRequest(proto::KeyAgentRequest),
        #[prost(message, tag = "4")]
        ImportKey(ImportKey),
        #[prost(message, tag = "5")]
        Exported(KeyTransfer),
    }
}

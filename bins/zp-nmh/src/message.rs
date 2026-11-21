//! The extension's requests and the bridge's answers, as JSON
//! (`docs/spec/extension.md` §3.3).

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;
use zeroize::Zeroizing;
use zp_ipc::IpcError;
use zp_ipc::proto::ErrorCode;

/// A request and the number the extension gave it.
#[derive(Deserialize)]
pub(crate) struct Envelope {
    pub(crate) id: u64,
    #[serde(flatten)]
    pub(crate) request: Request,
}

/// A secret in a request (a password the user typed): wiped when dropped,
/// never printed.
#[derive(Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub(crate) struct Secret(String);

impl Secret {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl core::fmt::Debug for Secret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("<secret>")
    }
}

/// What the extension asks.
#[derive(Deserialize, Debug, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum Request {
    /// Whether there is a vault, whether it runs, whether it is unlocked.
    Status,
    /// The logins that match a page.
    Find {
        origin: String,
        /// The tab's top frame, if the page is a frame.
        #[serde(default)]
        top: String,
    },
    /// The user name and password of one login, for a page it matches.
    Fill {
        origin: String,
        #[serde(default)]
        top: String,
        item: String,
    },
    /// The one-time code tied to a login of the page; Windows Hello asks.
    Totp {
        origin: String,
        #[serde(default)]
        top: String,
        item: String,
    },
    /// Whether what the user typed into the page is in the vault.
    Compare {
        origin: String,
        #[serde(default)]
        top: String,
        username: String,
        password: Secret,
    },
    /// Saves a new login for the page.
    Save {
        origin: String,
        #[serde(default)]
        top: String,
        #[serde(default)]
        title: String,
        username: String,
        password: Secret,
    },
    /// Replaces the password of a login of the page.
    Update {
        origin: String,
        #[serde(default)]
        top: String,
        item: String,
        password: Secret,
    },
    /// Makes a passkey for the page (`docs/spec/extension.md` §11); Windows
    /// Hello asks. Bytes are base64url.
    PasskeyCreate {
        origin: String,
        #[serde(default)]
        top: String,
        #[serde(default)]
        rp_id: String,
        #[serde(default)]
        rp_name: String,
        user_id: String,
        #[serde(default)]
        user_name: String,
        #[serde(default)]
        user_display_name: String,
        challenge: String,
        #[serde(default)]
        algorithms: Vec<i32>,
        #[serde(default)]
        exclude: Vec<String>,
    },
    /// Signs for the page with one of its passkeys; Windows Hello asks,
    /// except for the passkey picked from the choices of the same request.
    PasskeyGet {
        origin: String,
        #[serde(default)]
        top: String,
        #[serde(default)]
        rp_id: String,
        challenge: String,
        #[serde(default)]
        allow: Vec<String>,
        #[serde(default)]
        chosen: String,
    },
    /// Start the desktop application.
    OpenApp,
}

/// The number of a request that could not be read, if it has one.
pub(crate) fn id_of(bytes: &[u8]) -> u64 {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()
        .and_then(|value| value.get("id").and_then(serde_json::Value::as_u64))
        .unwrap_or(0)
}

/// A login that matches a page. No secret.
#[derive(Serialize)]
pub(crate) struct Login {
    pub(crate) id: String,
    pub(crate) title: String,
    pub(crate) username: String,
    pub(crate) r#match: &'static str,
}

/// What the bridge answers.
#[derive(Serialize)]
#[serde(untagged)]
pub(crate) enum Answer {
    Status {
        vault: bool,
        running: bool,
        unlocked: bool,
        totp: bool,
        /// Whether the vault keeps passkeys (has the passkey domain).
        passkeys: bool,
    },
    Logins {
        logins: Vec<Login>,
    },
    Credential {
        #[serde(serialize_with = "secret")]
        username: Zeroizing<String>,
        #[serde(serialize_with = "secret")]
        password: Zeroizing<String>,
    },
    Code {
        #[serde(serialize_with = "secret")]
        code: Zeroizing<String>,
    },
    Comparison {
        /// The login of the page with that user name, or empty.
        item: String,
        same: bool,
    },
    Saved {
        item: String,
    },
    /// A new passkey, as the page receives it. Bytes are base64url.
    PasskeyCreated {
        credential_id: String,
        client_data_json: String,
        attestation_object: String,
        authenticator_data: String,
        public_key: String,
        algorithm: i32,
    },
    /// An assertion, as the page receives it. Bytes are base64url.
    PasskeyAssertion {
        credential_id: String,
        client_data_json: String,
        authenticator_data: String,
        signature: String,
        user_handle: String,
    },
    /// Several passkeys fit: the user picks one.
    PasskeyChoices {
        choices: Vec<PasskeyChoice>,
    },
    Done {},
}

/// A passkey the user may pick. No secret.
#[derive(Serialize)]
pub(crate) struct PasskeyChoice {
    /// The credential identifier, base64url.
    pub(crate) credential_id: String,
    pub(crate) user_name: String,
    pub(crate) display_name: String,
}

fn secret<S: serde::Serializer>(
    value: &Zeroizing<String>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(value)
}

/// Why a request failed.
#[derive(Serialize, Debug)]
pub(crate) struct Failure {
    code: String,
    message: String,
}

impl Failure {
    pub(crate) fn new(code: &str, message: &str) -> Self {
        Self {
            code: code.to_owned(),
            message: message.to_owned(),
        }
    }

    pub(crate) fn not_running() -> Self {
        Self::new("NotRunning", "ZeroPass is not running: open ZeroPass")
    }

    pub(crate) fn is_not_running(&self) -> bool {
        self.code == "NotRunning"
    }

    /// The failure a client error stands for: the daemon's own code if it
    /// answered with one.
    pub(crate) fn from_client(error: &zp_client::Error) -> Self {
        if matches!(error, zp_client::Error::Ipc(IpcError::NotRunning)) {
            return Self::not_running();
        }
        match error.remote() {
            Some(remote) => Self {
                code: ErrorCode::try_from(remote.code)
                    .map_or_else(|_| "Internal".to_owned(), |code| format!("{code:?}")),
                message: remote.message.clone(),
            },
            None => Self::new("Internal", &error.to_string()),
        }
    }
}

/// One answer, as it goes to the extension.
#[derive(Serialize)]
pub(crate) struct Reply {
    id: u64,
    ok: bool,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    answer: Option<Answer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<Failure>,
}

impl Reply {
    pub(crate) fn new(id: u64, outcome: Result<Answer, Failure>) -> Self {
        match outcome {
            Ok(answer) => Self {
                id,
                ok: true,
                answer: Some(answer),
                error: None,
            },
            Err(failure) => Self {
                id,
                ok: false,
                answer: None,
                error: Some(failure),
            },
        }
    }
}

impl Drop for Failure {
    fn drop(&mut self) {
        self.message.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(json: &str) -> Envelope {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn requests_are_read() {
        let find = envelope(r#"{"id":3,"type":"find","origin":"https://example.com"}"#);
        assert_eq!(find.id, 3);
        assert_eq!(
            find.request,
            Request::Find {
                origin: "https://example.com".to_owned(),
                top: String::new(),
            }
        );
        assert_eq!(
            envelope(r#"{"id":1,"type":"status"}"#).request,
            Request::Status
        );
        assert_eq!(
            envelope(r#"{"id":1,"type":"open_app"}"#).request,
            Request::OpenApp
        );
        for bad in [
            r#"{"id":1,"type":"list"}"#,
            r#"{"id":1,"type":"fill","origin":"https://example.com"}"#,
            r#"{"type":"status"}"#,
            "[]",
        ] {
            assert!(serde_json::from_str::<Envelope>(bad).is_err(), "{bad}");
        }
        assert_eq!(id_of(br#"{"id":9,"type":"nonsense"}"#), 9);
        assert_eq!(id_of(b"not json"), 0);
    }

    #[test]
    fn answers_are_written_flat() {
        let reply = Reply::new(
            5,
            Ok(Answer::Credential {
                username: Zeroizing::new("alice".to_owned()),
                password: Zeroizing::new("hunter2".to_owned()),
            }),
        );
        assert_eq!(
            serde_json::to_string(&reply).unwrap(),
            r#"{"id":5,"ok":true,"username":"alice","password":"hunter2"}"#
        );
        let done = Reply::new(6, Ok(Answer::Done {}));
        assert_eq!(
            serde_json::to_string(&done).unwrap(),
            r#"{"id":6,"ok":true}"#
        );
        let failed = Reply::new(7, Err(Failure::new("Locked", "the vault is locked")));
        assert_eq!(
            serde_json::to_string(&failed).unwrap(),
            r#"{"id":7,"ok":false,"error":{"code":"Locked","message":"the vault is locked"}}"#
        );
    }
}

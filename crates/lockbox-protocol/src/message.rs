//! Wire messages for uploading and downloading files.
//!
//! Example flow of messages:
//! ```text
//! Upload     C: Upload
//!            S: Uploaded
//! Download   C: RequestDownload
//!            S: Challenge
//!            C: ChallengeResponse
//!            S: File | Error(NotAuthorized | InvalidSignature)
//! ```

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::file_id::FileId;

/// Length of a [`Challenge`] in bytes.
pub const CHALLENGE_LEN: usize = 32;

/// Random bytes issued by the server and signed by the client to prove it
/// holds the secret key for the public key it presents. The server issues a
/// fresh one for each download request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Challenge([u8; CHALLENGE_LEN]);

impl Challenge {
    pub fn random() -> Self {
        let mut bytes = [0u8; CHALLENGE_LEN];
        rand::fill(&mut bytes[..]);

        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; CHALLENGE_LEN] {
        &self.0
    }
}

impl From<[u8; CHALLENGE_LEN]> for Challenge {
    fn from(bytes: [u8; CHALLENGE_LEN]) -> Self {
        Self(bytes)
    }
}

/// Why the server refused a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    /// No file exists with this id.
    NotFound,
    /// The file existed but its ttl has elapsed.
    Expired,
    /// The signature is valid, but the key is not a recipient of the file.
    NotAuthorized,
    /// The signature does not verify for this key, challenge and file id.
    InvalidSignature,
    /// The message is malformed, or not valid in the current state (for
    /// example a `ChallengeResponse` with no challenge outstanding).
    InvalidRequest,
}

/// Messages sent by the client.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientMessage {
    /// Requests to store a file on the server.
    Upload {
        envelope_bytes: Vec<u8>,
        ttl_seconds: u64,
    },
    /// Requests a file stored on the server.
    RequestDownload(FileId),
    /// Answers a `Challenge` sent by the server.
    ChallengeResponse {
        public_key: VerifyingKey,
        signature: Signature,
    },
}

/// Messages sent by the server.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerMessage {
    /// The file is successfully stored on the server.
    Uploaded(FileId),
    /// Sends a challenge to the client to prove key ownership.
    Challenge(Challenge),
    /// The requested file.
    File {
        envelope_bytes: Vec<u8>
    },
    /// The request was refused. See [`ErrorCode`].
    Error(ErrorCode),
}

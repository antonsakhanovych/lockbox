use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("malformed key: {0}")]
    InvalidKey(#[from] ed25519_dalek::SignatureError),

    #[error("signature verification failed")]
    InvalidSignature,

    #[error("expected {expected} bytes, found {actual}")]
    WrongLength { expected: usize, actual: usize },

    #[error("invalid base64: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("i/o error on {}: {source}", path.display())]
    FileIo {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("private key encoding error: {0}")]
    Pkcs8(#[from] ed25519_dalek::pkcs8::Error),

    #[error("public key encoding error: {0}")]
    Spki(#[from] ed25519_dalek::pkcs8::spki::Error),

    #[error("encryption failed")]
    Encryption,

    #[error("decryption failed: wrong key or tampered data")]
    Decryption,

    #[error("weak recipient key")]
    WeakRecipientKey,

    #[error("at least one recipient is required")]
    NoRecipients,

    #[error("{count} recipients exceeds the limit of {max}")]
    TooManyRecipients { count: usize, max: usize },

    #[error("this key is not a recipient of the envelope")]
    NotARecipient,
}

pub type Result<T> = std::result::Result<T, CryptoError>;

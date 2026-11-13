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
}

pub type Result<T> = std::result::Result<T, CryptoError>;

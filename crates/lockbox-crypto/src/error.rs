#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("malformed key: {0}")]
    InvalidKey(#[from] ed25519_dalek::SignatureError),

    #[error("expected {expected} bytes, found {actual}")]
    WrongLength { expected: usize, actual: usize },

    #[error("invalid base64: {0}")]
    Base64(#[from] base64::DecodeError),
}

pub type Result<T> = std::result::Result<T, CryptoError>;

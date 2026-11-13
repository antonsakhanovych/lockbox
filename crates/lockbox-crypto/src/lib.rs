pub mod error;
pub mod keys;

pub use ed25519_dalek::SigningKey;
pub use error::{CryptoError, Result};

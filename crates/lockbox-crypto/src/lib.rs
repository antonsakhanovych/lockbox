mod domain;
pub mod error;
pub mod keys;
pub mod sign;

pub use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
pub use error::{CryptoError, Result};

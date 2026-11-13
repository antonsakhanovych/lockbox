use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use ed25519_dalek::{PUBLIC_KEY_LENGTH, SigningKey, VerifyingKey};

use crate::{CryptoError, Result};

pub fn generate_keypair() -> SigningKey {
    let mut csprng = rand::rng();
    SigningKey::generate(&mut csprng)
}

pub fn encode_public_key(key: &VerifyingKey) -> String {
    BASE64_STANDARD.encode(key)
}

pub fn decode_public_key(text: &str) -> Result<VerifyingKey> {
    let text = text.trim();
    let decoded = BASE64_STANDARD.decode(text)?;
    let bytes = <[u8; PUBLIC_KEY_LENGTH]>::try_from(decoded.as_slice()).map_err(|_| {
        CryptoError::WrongLength {
            expected: PUBLIC_KEY_LENGTH,
            actual: decoded.len(),
        }
    })?;
    let vkey = VerifyingKey::from_bytes(&bytes)?;
    Ok(vkey)
}

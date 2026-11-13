use crate::{
    CryptoError, Result,
    domain::{self, prepend_domain},
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

pub fn sign(message: &[u8], key: &SigningKey) -> Signature {
    key.sign(&prepend_domain(domain::SIGN, message))
}

pub fn verify(message: &[u8], signature: &Signature, key: &VerifyingKey) -> Result<()> {
    key.verify_strict(&prepend_domain(domain::SIGN, message), signature)
        .map_err(|_| CryptoError::InvalidSignature)
}

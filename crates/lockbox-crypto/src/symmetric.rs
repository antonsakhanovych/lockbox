use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use zeroize::Zeroizing;

use crate::{CryptoError, Result};

pub(crate) const KEY_LEN: usize = 32;
pub(crate) const NONCE_LEN: usize = 24;
pub(crate) const TAG_LEN: usize = 16;

pub(crate) struct SymmetricKey(Zeroizing<[u8; KEY_LEN]>);

impl SymmetricKey {
    pub(crate) fn random() -> Self {
        let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
        rand::fill(&mut bytes[..]);
        Self(bytes)
    }

    pub(crate) fn encrypt(&self, msg: &[u8], aad: &[u8]) -> Result<([u8; NONCE_LEN], Vec<u8>)> {
        let mut nonce = [0u8; NONCE_LEN];
        rand::fill(&mut nonce[..]);
        let ciphertext = self
            .cipher()
            .encrypt(&XNonce::from(nonce), Payload { msg, aad })
            .map_err(|_| CryptoError::Encryption)?;
        Ok((nonce, ciphertext))
    }

    pub(crate) fn decrypt(
        &self,
        nonce: &[u8; NONCE_LEN],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        self.cipher()
            .decrypt(
                &XNonce::from(*nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::Decryption)
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(&(*self.0).into())
    }
}

impl From<Zeroizing<[u8; KEY_LEN]>> for SymmetricKey {
    fn from(value: Zeroizing<[u8; KEY_LEN]>) -> Self {
        Self(value)
    }
}

impl AsRef<[u8; KEY_LEN]> for SymmetricKey {
    fn as_ref(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

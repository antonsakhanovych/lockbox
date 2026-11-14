//! Encrypts one file for several recipients.
//!
//! The file is encrypted once with a random data key. That key is then locked
//! separately for each recipient. Adding a recipient adds about 136 bytes.
//!
//! To lock the data key for one recipient:
//!
//! 1. Make a throwaway key pair. `e` is the secret, `e * G` the public point.
//! 2. Multiply the recipient's public key (`s * G`) by `e`. The result,
//!    `e * s * G`, is the shared secret.
//! 3. Hash the shared secret with a label and both public keys. That is the
//!    wrapping key.
//! 4. Encrypt the data key with the wrapping key.
//!
//! The recipient gets the same shared secret by multiplying the stored
//! `e * G` by their own secret `s`. Nobody else can, and `e` is thrown away.
//!
//! The envelope holds no secrets. Anyone who has it can see the recipients'
//! public keys. It does not prove who made it, and a recipient can still pass
//! the plaintext on.
//!
//! ```
//! # fn main() -> Result<(), lockbox_crypto::CryptoError> {
//! use lockbox_crypto::envelope::Envelope;
//! use lockbox_crypto::keys::generate_keypair;
//!
//! let alice = generate_keypair();
//! let bob = generate_keypair();
//!
//! let envelope = Envelope::encrypt_to_recipients(
//!     b"meet at noon",
//!     &[alice.verifying_key(), bob.verifying_key()],
//! )?;
//!
//! assert_eq!(envelope.decrypt(&alice)?, b"meet at noon");
//! assert_eq!(envelope.decrypt(&bob)?, b"meet at noon");
//! # Ok(())
//! # }
//! ```

use curve25519_dalek::MontgomeryPoint;
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    CryptoError, Result, domain,
    symmetric::{KEY_LEN, Nonce, SymmetricKey, TAG_LEN},
};

/// Format number. Stored in every envelope and used as AAD for the file, so
/// changing it breaks decryption.
pub const ENVELOPE_VERSION: u16 = 1;

/// `e * G`. Public.
type EphemeralPublic = [u8; KEY_LEN];

/// `e * s * G`. Secret, wiped on drop.
type SharedSecret = Zeroizing<[u8; KEY_LEN]>;

/// The data key plus its 16-byte tag.
type SealedKey = [u8; KEY_LEN + TAG_LEN];

/// A file encrypted for several recipients. It holds no secrets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    /// Format number, see `ENVELOPE_VERSION`.
    version: u16,
    /// Nonce for the file encryption.
    nonce: Nonce,
    /// One entry per recipient, in the order given.
    recipients: Vec<WrappedKey>,
    /// The encrypted file. The last 16 bytes are the tag.
    ciphertext: Vec<u8>,
}

impl Envelope {
    /// Encrypts `message` so every key in `recipients` can decrypt it.
    ///
    /// Fails with `NoRecipients` if the list is empty, and with
    /// `WeakRecipientKey` if a key gives an all-zero shared secret.
    pub fn encrypt_to_recipients(message: &[u8], recipients: &[VerifyingKey]) -> Result<Self> {
        if recipients.is_empty() {
            return Err(CryptoError::NoRecipients);
        }
        let data_key = SymmetricKey::random();
        let aad = Self::aad(ENVELOPE_VERSION);
        let (nonce, ciphertext) = data_key.encrypt(message, &aad)?;
        let recipients = recipients
            .iter()
            .map(|recipient| WrappedKey::seal(&data_key, recipient))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            version: ENVELOPE_VERSION,
            nonce,
            recipients,
            ciphertext,
        })
    }

    /// Decrypts with the secret key of one recipient.
    ///
    /// Fails with `NotARecipient` if the key has no entry, and with
    /// `Decryption` if the key is wrong or anything in the envelope changed.
    pub fn decrypt(&self, key: &SigningKey) -> Result<Vec<u8>> {
        let own = key.verifying_key();
        let wrapped_key = self
            .recipients
            .iter()
            .find(|&wrapped| wrapped.recipient == own)
            .ok_or(CryptoError::NotARecipient)?;
        let data_key = wrapped_key.open(key)?;
        data_key.decrypt(&self.nonce, &self.ciphertext, &Self::aad(ENVELOPE_VERSION))
    }

    /// The version as big endian bytes. It takes the version as an argument
    /// because no envelope exists yet when the file is encrypted.
    fn aad(version: u16) -> [u8; 2] {
        version.to_be_bytes()
    }
}

/// The data key locked for one recipient.
///
/// `G` is the curve's base point, `s` the recipient's secret number and `e`
/// the sender's throwaway secret.
#[derive(Clone, Debug, PartialEq, Eq)]
struct WrappedKey {
    /// `s * G`. Used to find your entry, and mixed into the hash and the AAD.
    recipient: VerifyingKey,
    /// `e * G`. The recipient needs it to rebuild the shared secret.
    ephemeral: EphemeralPublic,
    /// Nonce for locking the data key.
    nonce: Nonce,
    /// The data key encrypted with the wrapping key.
    sealed: SealedKey,
}

impl WrappedKey {
    /// Locks `data_key` for `recipient`. The ephemeral secret, the shared
    /// secret and the wrapping key are wiped before this returns.
    fn seal(data_key: &SymmetricKey, recipient: &VerifyingKey) -> Result<Self> {
        let mut ephemeral_secret = Zeroizing::new([0u8; KEY_LEN]);
        rand::fill(&mut ephemeral_secret[..]);
        let ephemeral = MontgomeryPoint::mul_base_clamped(*ephemeral_secret).to_bytes();
        let shared_secret = Zeroizing::new(
            recipient
                .to_montgomery()
                .mul_clamped(*ephemeral_secret)
                .to_bytes(),
        );
        if shared_secret.iter().all(|&byte| byte == 0) {
            return Err(CryptoError::WeakRecipientKey);
        }
        let wrapping_key = Self::wrapping_key(&shared_secret, &ephemeral, recipient);
        let aad = Self::aad(recipient, &ephemeral);
        let (nonce, sealed_key) = wrapping_key.encrypt(data_key.as_ref(), &aad)?;
        let sealed_key = SealedKey::try_from(sealed_key).map_err(|_| CryptoError::Encryption)?;
        Ok(Self {
            recipient: *recipient,
            ephemeral,
            nonce,
            sealed: sealed_key,
        })
    }

    /// Unlocks the data key with the recipient's secret key.
    ///
    /// It computes the shared secret as `s * (e * G)`, then uses the same
    /// `wrapping_key` and `aad` as `seal`. The scalar is clamped because the
    /// ephemeral point comes from untrusted data.
    fn open(&self, key: &SigningKey) -> Result<SymmetricKey> {
        let scalar = Zeroizing::new(key.to_scalar_bytes());
        let shared_secret = Zeroizing::new(
            MontgomeryPoint(self.ephemeral)
                .mul_clamped(*scalar)
                .to_bytes(),
        );
        let wrapping_key = Self::wrapping_key(&shared_secret, &self.ephemeral, &self.recipient);
        let aad = Self::aad(&self.recipient, &self.ephemeral);
        let data_key = Zeroizing::new(wrapping_key.decrypt(&self.nonce, &self.sealed, &aad)?);

        if data_key.len() != KEY_LEN {
            return Err(CryptoError::Decryption);
        }
        let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
        bytes.copy_from_slice(&data_key);
        Ok(SymmetricKey::from(bytes))
    }

    /// Hashes the shared secret with a label and both public keys. The input
    /// order is part of the format, so this is the only place it is done.
    fn wrapping_key(
        shared_secret: &SharedSecret,
        ephemeral: &EphemeralPublic,
        recipient: &VerifyingKey,
    ) -> SymmetricKey {
        let mut digest = Sha256::new()
            .chain_update(domain::KEY_WRAP)
            .chain_update(shared_secret)
            .chain_update(ephemeral)
            .chain_update(recipient.as_bytes())
            .finalize();
        let key = SymmetricKey::from(Zeroizing::new(digest.into()));
        digest.zeroize();
        key
    }

    /// The recipient key followed by the ephemeral point. Only public values,
    /// since it has to be rebuilt at decryption.
    fn aad(recipient: &VerifyingKey, ephemeral: &EphemeralPublic) -> [u8; 2 * KEY_LEN] {
        let mut aad = [0u8; 2 * KEY_LEN];
        aad[..KEY_LEN].copy_from_slice(recipient.as_bytes());
        aad[KEY_LEN..].copy_from_slice(ephemeral);
        aad
    }
}

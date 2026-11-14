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
//! # fn main() -> Result<(), lockbox_protocol::crypto::CryptoError> {
//! use lockbox_protocol::crypto::envelope::Envelope;
//! use lockbox_protocol::crypto::keys::generate_keypair;
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

use std::collections::HashSet;

use curve25519_dalek::MontgomeryPoint;
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{
    CryptoError, Result, domain,
    symmetric::{KEY_LEN, NONCE_LEN, Nonce, SymmetricKey, TAG_LEN},
};

/// Format number. Stored in every envelope and used as AAD for the file, so
/// changing it breaks decryption.
pub const ENVELOPE_VERSION: u16 = 1;

/// The most distinct recipients one envelope can have.
pub const MAX_RECIPIENTS: usize = 64;

/// `e * G`. Public.
type EphemeralPublic = [u8; KEY_LEN];

/// `e * s * G`. Secret, wiped on drop.
type SharedSecret = Zeroizing<[u8; KEY_LEN]>;

/// The data key plus its 16-byte tag.
type SealedKey = [u8; KEY_LEN + TAG_LEN];

/// Bytes before the first entry: version, file nonce and recipient count.
const HEADER_LEN: usize = 2 + NONCE_LEN + 2;

/// A file encrypted for several recipients. It holds no secrets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    /// Format number, see `ENVELOPE_VERSION`.
    version: u16,
    /// Nonce for the file encryption.
    nonce: Nonce,
    /// One entry per distinct recipient, in the order given.
    recipients: Vec<WrappedKey>,
    /// The encrypted file. The last 16 bytes are the tag.
    ciphertext: Vec<u8>,
}

impl Envelope {
    /// Encrypts `message` so every key in `recipients` can decrypt it.
    ///
    /// A key listed more than once gets one entry. Fails with `NoRecipients`
    /// if the list is empty, `TooManyRecipients` if it has more than
    /// `MAX_RECIPIENTS` distinct keys, and `WeakRecipientKey` if a key gives
    /// an all-zero shared secret.
    pub fn encrypt_to_recipients(message: &[u8], recipients: &[VerifyingKey]) -> Result<Self> {
        if recipients.is_empty() {
            return Err(CryptoError::NoRecipients);
        }
        let mut seen = HashSet::new();
        let unique: Vec<&VerifyingKey> =
            recipients.iter().filter(|key| seen.insert(**key)).collect();
        if unique.len() > MAX_RECIPIENTS {
            return Err(CryptoError::TooManyRecipients {
                count: unique.len(),
                max: MAX_RECIPIENTS,
            });
        }
        let data_key = SymmetricKey::random();
        let aad = Self::aad(ENVELOPE_VERSION);
        let (nonce, ciphertext) = data_key.encrypt(message, &aad)?;
        let recipients = unique
            .into_iter()
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

    /// The envelope as bytes, ready to store or send. All numbers are big
    /// endian.
    ///
    /// ```text
    /// version (2) | file nonce (24) | recipient count (2) | entries | ciphertext
    /// entry = recipient key (32) | ephemeral point (32) | nonce (24) | sealed key (48)
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            HEADER_LEN + self.recipients.len() * WrappedKey::LEN + self.ciphertext.len(),
        );
        bytes.extend_from_slice(&self.version.to_be_bytes());
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&(self.recipients.len() as u16).to_be_bytes());
        for wrapped in &self.recipients {
            wrapped.write_to(&mut bytes);
        }
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    /// Reads an envelope from bytes made by `to_bytes`.
    ///
    /// Fails with `UnsupportedVersion` for an unknown version, and with
    /// `MalformedEnvelope` if the bytes are too short, the recipient count is
    /// zero or above `MAX_RECIPIENTS`, a recipient key is invalid, or the
    /// ciphertext is shorter than a tag. It checks the structure only. A
    /// changed byte is caught when you decrypt.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader(bytes);
        let version = u16::from_be_bytes(reader.take()?);
        if version != ENVELOPE_VERSION {
            return Err(CryptoError::UnsupportedVersion(version));
        }
        let nonce = reader.take()?;
        let count = usize::from(u16::from_be_bytes(reader.take()?));
        if count == 0 || count > MAX_RECIPIENTS {
            return Err(CryptoError::MalformedEnvelope);
        }
        let recipients = (0..count)
            .map(|_| WrappedKey::read_from(&mut reader))
            .collect::<Result<Vec<_>>>()?;
        let ciphertext = reader.rest();
        if ciphertext.len() < TAG_LEN {
            return Err(CryptoError::MalformedEnvelope);
        }
        Ok(Self {
            version,
            nonce,
            recipients,
            ciphertext: ciphertext.to_vec(),
        })
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
    /// Size of one entry in bytes.
    const LEN: usize = KEY_LEN + KEY_LEN + NONCE_LEN + KEY_LEN + TAG_LEN;

    /// Appends the entry to `out`.
    fn write_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.recipient.as_bytes());
        out.extend_from_slice(&self.ephemeral);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.sealed);
    }

    /// Reads one entry. Fails if the bytes run out or the recipient key is
    /// not a valid key.
    fn read_from(reader: &mut Reader) -> Result<Self> {
        let recipient = VerifyingKey::from_bytes(&reader.take()?)
            .map_err(|_| CryptoError::MalformedEnvelope)?;
        Ok(Self {
            recipient,
            ephemeral: reader.take()?,
            nonce: reader.take()?,
            sealed: reader.take()?,
        })
    }

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

/// Reads fixed-size fields from the front of a byte slice.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    /// Takes the next `N` bytes, or fails if fewer are left.
    fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
        let (head, rest) = self
            .0
            .split_first_chunk::<N>()
            .ok_or(CryptoError::MalformedEnvelope)?;
        self.0 = rest;
        Ok(*head)
    }

    /// Everything not read yet.
    fn rest(self) -> &'a [u8] {
        self.0
    }
}

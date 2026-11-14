use ed25519_dalek::Signer;
use lockbox_protocol::crypto::keys::generate_keypair;
use lockbox_protocol::crypto::sign::{sign, verify};
use lockbox_protocol::crypto::{CryptoError, Signature};

#[test]
fn a_valid_signature_verifies() {
    let key = generate_keypair();
    let signature = sign(b"challenge", &key);
    verify(b"challenge", &signature, &key.verifying_key()).unwrap();
}

#[test]
fn an_empty_message_can_be_signed_and_verified() {
    let key = generate_keypair();
    let signature = sign(b"", &key);
    verify(b"", &signature, &key.verifying_key()).unwrap();
}

#[test]
fn a_large_message_can_be_signed_and_verified() {
    let key = generate_keypair();
    let message = vec![0xA5u8; 1024 * 1024];
    let signature = sign(&message, &key);
    verify(&message, &signature, &key.verifying_key()).unwrap();
}

#[test]
fn a_signature_from_another_key_is_rejected() {
    let signer = generate_keypair();
    let other = generate_keypair();
    let signature = sign(b"challenge", &signer);
    assert!(matches!(
        verify(b"challenge", &signature, &other.verifying_key()),
        Err(CryptoError::InvalidSignature)
    ));
}

#[test]
fn a_changed_message_is_rejected() {
    let key = generate_keypair();
    let signature = sign(b"challenge", &key);
    let public = key.verifying_key();
    assert!(matches!(
        verify(b"challenge!", &signature, &public),
        Err(CryptoError::InvalidSignature)
    ));
    assert!(matches!(
        verify(b"Challenge", &signature, &public),
        Err(CryptoError::InvalidSignature)
    ));
    assert!(matches!(
        verify(b"", &signature, &public),
        Err(CryptoError::InvalidSignature)
    ));
}

#[test]
fn a_flipped_signature_bit_is_rejected() {
    let key = generate_keypair();
    let mut bytes = sign(b"challenge", &key).to_bytes();
    bytes[0] ^= 1;
    let tampered = Signature::from_bytes(&bytes);
    assert!(matches!(
        verify(b"challenge", &tampered, &key.verifying_key()),
        Err(CryptoError::InvalidSignature)
    ));
}

#[test]
fn a_signature_without_the_domain_label_is_rejected() {
    let key = generate_keypair();
    let raw = key.sign(b"challenge");
    assert!(matches!(
        verify(b"challenge", &raw, &key.verifying_key()),
        Err(CryptoError::InvalidSignature)
    ));
}

#[test]
fn signing_is_deterministic() {
    let key = generate_keypair();
    assert_eq!(sign(b"challenge", &key), sign(b"challenge", &key));
}

#[test]
fn different_messages_give_different_signatures() {
    let key = generate_keypair();
    assert_ne!(sign(b"one", &key), sign(b"two", &key));
}

#[test]
fn a_signature_survives_being_serialized_to_bytes() {
    let key = generate_keypair();
    let signature = sign(b"challenge", &key);
    let restored = Signature::from_bytes(&signature.to_bytes());
    verify(b"challenge", &restored, &key.verifying_key()).unwrap();
}

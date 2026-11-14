use lockbox_crypto::envelope::Envelope;
use lockbox_crypto::keys::generate_keypair;
use lockbox_crypto::{CryptoError, SigningKey, VerifyingKey};

fn recipients(count: usize) -> (Vec<SigningKey>, Vec<VerifyingKey>) {
    let secrets: Vec<SigningKey> = (0..count).map(|_| generate_keypair()).collect();
    let publics = secrets.iter().map(SigningKey::verifying_key).collect();
    (secrets, publics)
}

#[test]
fn a_single_recipient_can_decrypt() {
    let (secrets, publics) = recipients(1);
    let envelope = Envelope::encrypt_to_recipients(b"attack at dawn", &publics).unwrap();
    assert_eq!(envelope.decrypt(&secrets[0]).unwrap(), b"attack at dawn");
}

#[test]
fn every_recipient_can_decrypt_the_same_envelope() {
    let (secrets, publics) = recipients(5);
    let envelope = Envelope::encrypt_to_recipients(b"shared secret", &publics).unwrap();
    for secret in &secrets {
        assert_eq!(envelope.decrypt(secret).unwrap(), b"shared secret");
    }
}

#[test]
fn a_key_that_is_not_a_recipient_cannot_decrypt() {
    let (_, publics) = recipients(2);
    let outsider = generate_keypair();
    let envelope = Envelope::encrypt_to_recipients(b"private", &publics).unwrap();
    assert!(matches!(
        envelope.decrypt(&outsider),
        Err(CryptoError::NotARecipient)
    ));
}

#[test]
fn empty_and_large_payloads_round_trip() {
    let (secrets, publics) = recipients(2);

    let empty = Envelope::encrypt_to_recipients(b"", &publics).unwrap();
    assert_eq!(empty.decrypt(&secrets[1]).unwrap(), b"");

    let large = vec![0xA5u8; 3 * 1024 * 1024 + 7];
    let envelope = Envelope::encrypt_to_recipients(&large, &publics).unwrap();
    assert_eq!(envelope.decrypt(&secrets[0]).unwrap(), large);
}

#[test]
fn an_empty_recipient_list_is_rejected() {
    assert!(matches!(
        Envelope::encrypt_to_recipients(b"x", &[]),
        Err(CryptoError::NoRecipients)
    ));
}

#[test]
fn encrypting_twice_gives_different_envelopes() {
    let (secrets, publics) = recipients(1);
    let first = Envelope::encrypt_to_recipients(b"same", &publics).unwrap();
    let second = Envelope::encrypt_to_recipients(b"same", &publics).unwrap();
    assert_ne!(first, second);
    assert_eq!(first.decrypt(&secrets[0]).unwrap(), b"same");
    assert_eq!(second.decrypt(&secrets[0]).unwrap(), b"same");
}

#[test]
fn an_envelope_does_not_open_for_another_envelopes_recipient() {
    let (secrets_a, publics_a) = recipients(1);
    let (secrets_b, publics_b) = recipients(1);
    let for_a = Envelope::encrypt_to_recipients(b"for a", &publics_a).unwrap();
    let for_b = Envelope::encrypt_to_recipients(b"for b", &publics_b).unwrap();
    assert_eq!(for_a.decrypt(&secrets_a[0]).unwrap(), b"for a");
    assert_eq!(for_b.decrypt(&secrets_b[0]).unwrap(), b"for b");
    assert!(for_a.decrypt(&secrets_b[0]).is_err());
    assert!(for_b.decrypt(&secrets_a[0]).is_err());
}

#[test]
fn a_recipient_loaded_from_a_key_file_can_decrypt() {
    use lockbox_crypto::keys::{
        load_public_key, load_secret_key, save_public_key, save_secret_key,
    };

    let dir = tempfile::tempdir().unwrap();
    let secret = generate_keypair();
    save_secret_key(&dir.path().join("id.pem"), &secret).unwrap();
    save_public_key(&dir.path().join("id.pub.pem"), &secret.verifying_key()).unwrap();

    let recipient = load_public_key(&dir.path().join("id.pub.pem")).unwrap();
    let envelope = Envelope::encrypt_to_recipients(b"through files", &[recipient]).unwrap();
    let loaded = load_secret_key(&dir.path().join("id.pem")).unwrap();
    assert_eq!(envelope.decrypt(&loaded).unwrap(), b"through files");
}

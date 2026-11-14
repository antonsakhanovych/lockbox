use lockbox_crypto::envelope::{ENVELOPE_VERSION, Envelope, MAX_RECIPIENTS};
use lockbox_crypto::keys::generate_keypair;
use lockbox_crypto::{CryptoError, SigningKey, VerifyingKey};

const HEADER_LEN: usize = 2 + 24 + 2;
const ENTRY_LEN: usize = 32 + 32 + 24 + 48;
const TAG_LEN: usize = 16;

fn recipients(count: usize) -> (Vec<SigningKey>, Vec<VerifyingKey>) {
    let secrets: Vec<SigningKey> = (0..count).map(|_| generate_keypair()).collect();
    let publics = secrets.iter().map(SigningKey::verifying_key).collect();
    (secrets, publics)
}

fn open(bytes: &[u8], key: &SigningKey) -> Result<Vec<u8>, CryptoError> {
    Envelope::from_bytes(bytes).and_then(|envelope| envelope.decrypt(key))
}

#[test]
fn an_envelope_round_trips_through_bytes() {
    let (secrets, publics) = recipients(3);
    let envelope = Envelope::encrypt_to_recipients(b"over the wire", &publics).unwrap();
    let parsed = Envelope::from_bytes(&envelope.to_bytes()).unwrap();
    assert_eq!(parsed, envelope);
    for secret in &secrets {
        assert_eq!(parsed.decrypt(secret).unwrap(), b"over the wire");
    }
}

#[test]
fn large_and_empty_payloads_round_trip_through_bytes() {
    let (secrets, publics) = recipients(1);
    let large = vec![0x5Au8; 3 * 1024 * 1024 + 1];
    for message in [&b""[..], &large[..]] {
        let envelope = Envelope::encrypt_to_recipients(message, &publics).unwrap();
        assert_eq!(open(&envelope.to_bytes(), &secrets[0]).unwrap(), message);
    }
}

#[test]
fn the_maximum_number_of_recipients_round_trips_through_bytes() {
    let (secrets, publics) = recipients(MAX_RECIPIENTS);
    let envelope = Envelope::encrypt_to_recipients(b"full", &publics).unwrap();
    let bytes = envelope.to_bytes();
    assert_eq!(open(&bytes, &secrets[0]).unwrap(), b"full");
    assert_eq!(open(&bytes, &secrets[MAX_RECIPIENTS - 1]).unwrap(), b"full");
}

#[test]
fn the_layout_has_the_documented_size_and_header() {
    let message = b"fixed layout";
    for count in [1usize, 2, 5] {
        let (_, publics) = recipients(count);
        let bytes = Envelope::encrypt_to_recipients(message, &publics)
            .unwrap()
            .to_bytes();
        assert_eq!(
            bytes.len(),
            HEADER_LEN + count * ENTRY_LEN + message.len() + TAG_LEN
        );
        assert_eq!(bytes[..2], ENVELOPE_VERSION.to_be_bytes());
        assert_eq!(bytes[26..28], (count as u16).to_be_bytes());
        assert_eq!(&bytes[28..60], publics[0].as_bytes());
    }
}

#[test]
fn a_duplicate_recipient_adds_no_bytes() {
    let (_, publics) = recipients(2);
    let once = Envelope::encrypt_to_recipients(b"x", &publics).unwrap();
    let repeated = [publics[0], publics[1], publics[0], publics[1]];
    let twice = Envelope::encrypt_to_recipients(b"x", &repeated).unwrap();
    assert_eq!(once.to_bytes().len(), twice.to_bytes().len());
}

#[test]
fn changing_any_byte_of_a_single_recipient_envelope_is_detected() {
    let (secrets, publics) = recipients(1);
    let bytes = Envelope::encrypt_to_recipients(b"integrity matters", &publics)
        .unwrap()
        .to_bytes();
    for index in 0..bytes.len() {
        for mask in [0x01u8, 0x80] {
            let mut tampered = bytes.clone();
            tampered[index] ^= mask;
            assert!(
                open(&tampered, &secrets[0]).is_err(),
                "byte {index} with mask {mask:#04x} was not detected"
            );
        }
    }
}

#[test]
fn changing_a_byte_never_makes_anyone_read_a_different_message() {
    let (secrets, publics) = recipients(3);
    let message = b"integrity matters";
    let bytes = Envelope::encrypt_to_recipients(message, &publics)
        .unwrap()
        .to_bytes();
    for index in 0..bytes.len() {
        let mut tampered = bytes.clone();
        tampered[index] ^= 0x01;
        for secret in &secrets {
            if let Ok(plaintext) = open(&tampered, secret) {
                assert_eq!(plaintext, message, "byte {index} changed the message");
            }
        }
    }
}

#[test]
fn damaging_one_entry_only_affects_its_own_recipient() {
    let (secrets, publics) = recipients(3);
    let bytes = Envelope::encrypt_to_recipients(b"independent", &publics)
        .unwrap()
        .to_bytes();
    let second_entry = HEADER_LEN + ENTRY_LEN;
    let mut tampered = bytes.clone();
    tampered[second_entry + 70] ^= 0x01;
    assert_eq!(open(&tampered, &secrets[0]).unwrap(), b"independent");
    assert!(open(&tampered, &secrets[1]).is_err());
    assert_eq!(open(&tampered, &secrets[2]).unwrap(), b"independent");
}

#[test]
fn every_truncation_is_rejected() {
    let (secrets, publics) = recipients(2);
    let bytes = Envelope::encrypt_to_recipients(b"cut me short", &publics)
        .unwrap()
        .to_bytes();
    for length in 0..bytes.len() {
        assert!(
            open(&bytes[..length], &secrets[0]).is_err(),
            "length {length} was accepted"
        );
    }
}

#[test]
fn extra_trailing_bytes_are_rejected() {
    let (secrets, publics) = recipients(1);
    let mut bytes = Envelope::encrypt_to_recipients(b"exact", &publics)
        .unwrap()
        .to_bytes();
    bytes.push(0);
    assert!(open(&bytes, &secrets[0]).is_err());
}

#[test]
fn an_unknown_version_is_reported() {
    let (_, publics) = recipients(1);
    let mut bytes = Envelope::encrypt_to_recipients(b"x", &publics)
        .unwrap()
        .to_bytes();
    bytes[..2].copy_from_slice(&(ENVELOPE_VERSION + 1).to_be_bytes());
    assert!(matches!(
        Envelope::from_bytes(&bytes),
        Err(CryptoError::UnsupportedVersion(version)) if version == ENVELOPE_VERSION + 1
    ));
}

#[test]
fn a_bad_recipient_count_is_rejected() {
    let (_, publics) = recipients(1);
    let bytes = Envelope::encrypt_to_recipients(b"x", &publics)
        .unwrap()
        .to_bytes();
    for count in [0u16, MAX_RECIPIENTS as u16 + 1, u16::MAX] {
        let mut tampered = bytes.clone();
        tampered[26..28].copy_from_slice(&count.to_be_bytes());
        assert!(matches!(
            Envelope::from_bytes(&tampered),
            Err(CryptoError::MalformedEnvelope)
        ));
    }
}

#[test]
fn garbage_and_empty_input_are_rejected() {
    assert!(matches!(
        Envelope::from_bytes(&[]),
        Err(CryptoError::MalformedEnvelope)
    ));
    assert!(Envelope::from_bytes(&[0xFF; 300]).is_err());
    assert!(Envelope::from_bytes(&[0u8; 300]).is_err());
}

#[test]
fn a_ciphertext_shorter_than_a_tag_is_rejected() {
    let (_, publics) = recipients(1);
    let bytes = Envelope::encrypt_to_recipients(b"", &publics)
        .unwrap()
        .to_bytes();
    let cut = bytes.len() - TAG_LEN + 1;
    assert!(matches!(
        Envelope::from_bytes(&bytes[..cut]),
        Err(CryptoError::MalformedEnvelope)
    ));
}

#[test]
fn an_entry_moved_to_another_envelope_does_not_open() {
    let (secrets_a, publics_a) = recipients(1);
    let (_, publics_b) = recipients(1);
    let first = Envelope::encrypt_to_recipients(b"first", &publics_a)
        .unwrap()
        .to_bytes();
    let second = Envelope::encrypt_to_recipients(b"second", &publics_b)
        .unwrap()
        .to_bytes();
    let mut spliced = first.clone();
    spliced[HEADER_LEN..HEADER_LEN + ENTRY_LEN]
        .copy_from_slice(&second[HEADER_LEN..HEADER_LEN + ENTRY_LEN]);
    assert!(open(&spliced, &secrets_a[0]).is_err());
    assert_eq!(open(&first, &secrets_a[0]).unwrap(), b"first");
}

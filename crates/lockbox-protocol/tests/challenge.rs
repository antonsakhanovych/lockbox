use std::collections::HashSet;
use std::io::Cursor;

mod common;

use lockbox_protocol::challenge::{CHALLENGE_NONCE_LEN, CHALLENGE_TTL_SECS, SIGNING_BYTES_LEN};
use lockbox_protocol::codec::{read_message, write_message};
use lockbox_protocol::crypto::keys::generate_keypair;
use lockbox_protocol::crypto::sign::{sign, verify};
use lockbox_protocol::{Challenge, FileId, ProtocolError, Purpose};

const WIRE_LEN: usize = 16 + 1 + CHALLENGE_NONCE_LEN + 1;
const PURPOSE_AT: usize = 16;
const NONCE_AT: usize = 17;
const ISSUED_AT_AT: usize = 49;

async fn encode(challenge: &Challenge) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_message(&mut bytes, challenge).await.unwrap();
    common::body(bytes)
}

async fn decode(bytes: &[u8]) -> Result<Challenge, ProtocolError> {
    read_message(&mut Cursor::new(common::frame(bytes))).await
}

#[test]
fn a_challenge_keeps_what_it_was_made_with() {
    let id = FileId::random();
    let challenge = Challenge::new(id, Purpose::Delete, 1_700_000_000);
    assert_eq!(challenge.file_id(), id);
    assert_eq!(challenge.purpose(), Purpose::Delete);
    assert_eq!(challenge.issued_at(), 1_700_000_000);
}

#[test]
fn every_challenge_has_its_own_nonce() {
    let id = FileId::random();
    let nonces: HashSet<[u8; CHALLENGE_NONCE_LEN]> = (0..1000)
        .map(|_| *Challenge::new(id, Purpose::Fetch, 0).nonce())
        .collect();
    assert_eq!(nonces.len(), 1000);
}

#[test]
fn a_challenge_is_live_for_exactly_its_lifetime() {
    let challenge = Challenge::new(FileId::random(), Purpose::Fetch, 1000);
    assert!(challenge.is_live_at(1000));
    assert!(challenge.is_live_at(1000 + CHALLENGE_TTL_SECS - 1));
    assert!(!challenge.is_live_at(1000 + CHALLENGE_TTL_SECS));
    assert!(!challenge.is_live_at(1000 + CHALLENGE_TTL_SECS + 1));
    assert!(!challenge.is_live_at(u64::MAX));
}

#[test]
fn a_challenge_is_not_live_before_it_was_issued() {
    let challenge = Challenge::new(FileId::random(), Purpose::Fetch, 1000);
    assert!(!challenge.is_live_at(999));
    assert!(!challenge.is_live_at(0));
}

#[test]
fn liveness_does_not_overflow_near_the_end_of_time() {
    let challenge = Challenge::new(FileId::random(), Purpose::Fetch, u64::MAX);
    assert!(challenge.is_live_at(u64::MAX));
    assert!(!challenge.is_live_at(0));
}

#[test]
fn the_signing_bytes_have_a_fixed_layout() {
    let id = FileId::from(std::array::from_fn(|i| 0x10 + i as u8));
    let fetch = Challenge::new(id, Purpose::Fetch, 0x0102_0304_0506_0708);
    let delete = Challenge::new(id, Purpose::Delete, 0x0102_0304_0506_0708);

    let bytes = fetch.signing_bytes();
    assert_eq!(bytes.len(), SIGNING_BYTES_LEN);
    assert_eq!(bytes[0], 1);
    assert_eq!(&bytes[1..17], id.as_bytes());
    assert_eq!(&bytes[17..49], fetch.nonce());
    assert_eq!(&bytes[49..], [1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(delete.signing_bytes()[0], 2);
    assert_eq!(Challenge::new(id, Purpose::Upload, 0).signing_bytes()[0], 3);
}

#[tokio::test]
async fn on_the_wire_a_challenge_has_a_known_layout() {
    let id = FileId::random();
    let challenge = Challenge::new(id, Purpose::Delete, 5);
    let bytes = encode(&challenge).await;
    assert_eq!(bytes.len(), WIRE_LEN);
    assert_eq!(&bytes[..PURPOSE_AT], id.as_bytes());
    assert_eq!(bytes[PURPOSE_AT], 1);
    assert_eq!(&bytes[NONCE_AT..ISSUED_AT_AT], challenge.nonce());
    assert_eq!(bytes[ISSUED_AT_AT], 5);
    assert_eq!(decode(&bytes).await.unwrap(), challenge);
}

#[tokio::test]
async fn an_unknown_purpose_is_rejected() {
    let mut bytes = encode(&Challenge::new(FileId::random(), Purpose::Fetch, 5)).await;
    bytes[PURPOSE_AT] = 3;
    assert!(matches!(
        decode(&bytes).await,
        Err(ProtocolError::Decode(_))
    ));
}

#[tokio::test]
async fn every_purpose_round_trips() {
    for purpose in [Purpose::Fetch, Purpose::Delete, Purpose::Upload] {
        let challenge = Challenge::new(FileId::random(), purpose, 5);
        assert_eq!(decode(&encode(&challenge).await).await.unwrap(), challenge);
    }
}

#[tokio::test]
async fn a_signature_for_one_purpose_does_not_verify_as_another() {
    let key = generate_keypair();
    let purposes = [Purpose::Fetch, Purpose::Delete, Purpose::Upload];
    for (signed_index, signed_purpose) in purposes.into_iter().enumerate() {
        let challenge = Challenge::new(FileId::random(), signed_purpose, 5);
        let signature = sign(&challenge.signing_bytes(), &key);
        let wire = encode(&challenge).await;
        for (other_index, _) in purposes.into_iter().enumerate() {
            let mut bytes = wire.clone();
            bytes[PURPOSE_AT] = other_index as u8;
            let other = decode(&bytes).await.unwrap();
            let verified = verify(&other.signing_bytes(), &signature, &key.verifying_key()).is_ok();
            assert_eq!(verified, other_index == signed_index);
        }
    }
}

#[test]
fn a_signature_over_a_challenge_verifies() {
    let key = generate_keypair();
    let challenge = Challenge::new(FileId::random(), Purpose::Fetch, 77);
    let signature = sign(&challenge.signing_bytes(), &key);
    assert!(verify(&challenge.signing_bytes(), &signature, &key.verifying_key()).is_ok());
}

#[tokio::test]
async fn changing_any_field_breaks_the_signature() {
    let key = generate_keypair();
    let challenge = Challenge::new(FileId::random(), Purpose::Fetch, 77);
    let signature = sign(&challenge.signing_bytes(), &key);
    let wire = encode(&challenge).await;

    let mut tampered = Vec::new();
    for range in [
        0..16,
        PURPOSE_AT..NONCE_AT,
        NONCE_AT..ISSUED_AT_AT,
        ISSUED_AT_AT..WIRE_LEN,
    ] {
        let mut bytes = wire.clone();
        let last = range.end - 1;
        bytes[last] ^= 0x01;
        tampered.push(bytes);
    }
    let mut delete_instead = wire.clone();
    delete_instead[PURPOSE_AT] = 1;
    tampered.push(delete_instead);

    for bytes in tampered {
        let other = decode(&bytes).await.unwrap();
        assert_ne!(other, challenge);
        assert_ne!(other.signing_bytes(), challenge.signing_bytes());
        assert!(verify(&other.signing_bytes(), &signature, &key.verifying_key()).is_err());
    }
}

#[test]
fn a_signature_from_another_key_does_not_verify() {
    let challenge = Challenge::new(FileId::random(), Purpose::Fetch, 77);
    let signature = sign(&challenge.signing_bytes(), &generate_keypair());
    assert!(
        verify(
            &challenge.signing_bytes(),
            &signature,
            &generate_keypair().verifying_key()
        )
        .is_err()
    );
}

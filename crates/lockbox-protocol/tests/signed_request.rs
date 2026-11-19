use std::io::Cursor;

use lockbox_protocol::challenge::CHALLENGE_TTL_SECS;
use lockbox_protocol::codec::{read_message, write_message};
use lockbox_protocol::crypto::CryptoError;
use lockbox_protocol::crypto::keys::generate_keypair;
use lockbox_protocol::crypto::sign::sign;
use lockbox_protocol::{Challenge, FileId, ProtocolError, Purpose, SignedRequest};

const ISSUED_AT: u64 = 1_700_000_000;

fn challenge(purpose: Purpose) -> Challenge {
    Challenge::new(FileId::random(), purpose, ISSUED_AT)
}

#[test]
fn an_answer_carries_the_challenge_identity_and_the_signers_key() {
    let key = generate_keypair();
    let challenge = challenge(Purpose::Fetch);
    let answer = SignedRequest::answer(&challenge, &key);
    assert_eq!(answer.file_id, challenge.file_id());
    assert_eq!(&answer.nonce, challenge.nonce());
    assert_eq!(answer.public_key, key.verifying_key());
}

#[test]
fn a_correct_answer_passes_for_every_purpose() {
    let key = generate_keypair();
    for purpose in [Purpose::Fetch, Purpose::Delete, Purpose::Upload] {
        let challenge = challenge(purpose);
        let answer = SignedRequest::answer(&challenge, &key);
        assert!(answer.check(&challenge, purpose, ISSUED_AT).is_ok());
    }
}

#[test]
fn an_answer_passes_until_the_challenge_expires() {
    let key = generate_keypair();
    let challenge = challenge(Purpose::Fetch);
    let answer = SignedRequest::answer(&challenge, &key);
    let last_good = ISSUED_AT + CHALLENGE_TTL_SECS - 1;
    assert!(answer.check(&challenge, Purpose::Fetch, last_good).is_ok());
    assert!(matches!(
        answer.check(&challenge, Purpose::Fetch, last_good + 1),
        Err(ProtocolError::ChallengeExpired)
    ));
    assert!(matches!(
        answer.check(&challenge, Purpose::Fetch, ISSUED_AT - 1),
        Err(ProtocolError::ChallengeExpired)
    ));
}

#[test]
fn an_answer_for_another_purpose_is_rejected() {
    let key = generate_keypair();
    let challenge = challenge(Purpose::Fetch);
    let answer = SignedRequest::answer(&challenge, &key);
    for purpose in [Purpose::Delete, Purpose::Upload] {
        assert!(matches!(
            answer.check(&challenge, purpose, ISSUED_AT),
            Err(ProtocolError::ChallengeMismatch)
        ));
    }
}

#[test]
fn an_answer_for_another_file_is_rejected() {
    let key = generate_keypair();
    let challenge = challenge(Purpose::Fetch);
    let mut answer = SignedRequest::answer(&challenge, &key);
    answer.file_id = FileId::random();
    assert!(matches!(
        answer.check(&challenge, Purpose::Fetch, ISSUED_AT),
        Err(ProtocolError::ChallengeMismatch)
    ));
}

#[test]
fn an_answer_with_another_nonce_is_rejected() {
    let key = generate_keypair();
    let challenge = challenge(Purpose::Fetch);
    let mut answer = SignedRequest::answer(&challenge, &key);
    answer.nonce[0] ^= 0x01;
    assert!(matches!(
        answer.check(&challenge, Purpose::Fetch, ISSUED_AT),
        Err(ProtocolError::ChallengeMismatch)
    ));
}

#[test]
fn an_answer_to_another_challenge_for_the_same_file_is_rejected() {
    let key = generate_keypair();
    let first = challenge(Purpose::Fetch);
    let second = Challenge::new(first.file_id(), Purpose::Fetch, ISSUED_AT);
    let answer = SignedRequest::answer(&first, &key);
    assert!(matches!(
        answer.check(&second, Purpose::Fetch, ISSUED_AT),
        Err(ProtocolError::ChallengeMismatch)
    ));
}

#[test]
fn a_signature_from_another_key_is_rejected() {
    let challenge = challenge(Purpose::Fetch);
    let mut answer = SignedRequest::answer(&challenge, &generate_keypair());
    answer.public_key = generate_keypair().verifying_key();
    assert!(matches!(
        answer.check(&challenge, Purpose::Fetch, ISSUED_AT),
        Err(ProtocolError::Crypto(CryptoError::InvalidSignature))
    ));
}

#[test]
fn a_signature_over_another_challenge_is_rejected() {
    let key = generate_keypair();
    let challenge = challenge(Purpose::Fetch);
    let other = self::challenge(Purpose::Fetch);
    let mut answer = SignedRequest::answer(&challenge, &key);
    answer.signature = sign(&other.signing_bytes(), &key);
    assert!(matches!(
        answer.check(&challenge, Purpose::Fetch, ISSUED_AT),
        Err(ProtocolError::Crypto(CryptoError::InvalidSignature))
    ));
}

#[test]
fn an_expired_answer_is_reported_as_expired_even_if_the_signature_is_good() {
    let key = generate_keypair();
    let challenge = challenge(Purpose::Delete);
    let answer = SignedRequest::answer(&challenge, &key);
    assert!(matches!(
        answer.check(&challenge, Purpose::Delete, ISSUED_AT + 10_000),
        Err(ProtocolError::ChallengeExpired)
    ));
}

#[tokio::test]
async fn an_answer_still_checks_after_travelling_over_the_wire() {
    let key = generate_keypair();
    let challenge = challenge(Purpose::Upload);
    let answer = SignedRequest::answer(&challenge, &key);
    let mut bytes = Vec::new();
    write_message(&mut bytes, &answer).await.unwrap();
    let received: SignedRequest = read_message(&mut Cursor::new(bytes)).await.unwrap();
    assert_eq!(received, answer);
    assert!(
        received
            .check(&challenge, Purpose::Upload, ISSUED_AT)
            .is_ok()
    );
}

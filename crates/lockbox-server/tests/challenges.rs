mod common;

use std::sync::Arc;

use common::TestClock;
use lockbox_protocol::challenge::CHALLENGE_TTL_SECS;
use lockbox_protocol::crypto::keys::generate_keypair;
use lockbox_protocol::{FileId, Purpose, SignedRequest};
use lockbox_server::core::error::CoreError;
use lockbox_server::core::services::Challenges;

const START: u64 = 1_000_000;

fn setup() -> (Arc<TestClock>, Challenges<TestClock>) {
    let clock = TestClock::at(START);
    let challenges = Challenges::new(clock.clone());
    (clock, challenges)
}

#[test]
fn a_challenge_is_bound_to_the_file_the_purpose_and_the_time() {
    let (_clock, challenges) = setup();
    let id = FileId::random();
    let challenge = challenges.issue(id, Purpose::Fetch);
    assert_eq!(challenge.file_id(), id);
    assert_eq!(challenge.purpose(), Purpose::Fetch);
    assert_eq!(challenge.issued_at(), START);
}

#[test]
fn every_challenge_has_its_own_nonce() {
    let (_clock, challenges) = setup();
    let id = FileId::random();
    let first = challenges.issue(id, Purpose::Fetch);
    let second = challenges.issue(id, Purpose::Fetch);
    assert_ne!(first.nonce(), second.nonce());
}

#[test]
fn a_correct_answer_is_accepted_and_names_the_file_and_the_key() {
    let (_clock, challenges) = setup();
    let key = generate_keypair();
    let id = FileId::random();
    let challenge = challenges.issue(id, Purpose::Delete);
    let proof = SignedRequest::answer(&challenge, &key);
    let verified = challenges
        .verify(challenge, &proof, Purpose::Delete)
        .unwrap();
    assert_eq!(verified.file_id(), id);
    assert_eq!(verified.key(), &key.verifying_key());
}

#[test]
fn an_answer_for_one_purpose_is_denied_for_another() {
    let (_clock, challenges) = setup();
    let key = generate_keypair();
    let challenge = challenges.issue(FileId::random(), Purpose::Fetch);
    let proof = SignedRequest::answer(&challenge, &key);
    assert!(matches!(
        challenges.verify(challenge, &proof, Purpose::Delete),
        Err(CoreError::Denied)
    ));
}

#[test]
fn a_signature_from_a_different_key_is_denied() {
    let (_clock, challenges) = setup();
    let challenge = challenges.issue(FileId::random(), Purpose::Fetch);
    let mut proof = SignedRequest::answer(&challenge, &generate_keypair());
    proof.public_key = generate_keypair().verifying_key();
    assert!(matches!(
        challenges.verify(challenge, &proof, Purpose::Fetch),
        Err(CoreError::Denied)
    ));
}

#[test]
fn an_answer_for_another_file_is_denied() {
    let (_clock, challenges) = setup();
    let challenge = challenges.issue(FileId::random(), Purpose::Fetch);
    let mut proof = SignedRequest::answer(&challenge, &generate_keypair());
    proof.file_id = FileId::random();
    assert!(matches!(
        challenges.verify(challenge, &proof, Purpose::Fetch),
        Err(CoreError::Denied)
    ));
}

#[test]
fn an_answer_with_another_nonce_is_denied() {
    let (_clock, challenges) = setup();
    let challenge = challenges.issue(FileId::random(), Purpose::Fetch);
    let mut proof = SignedRequest::answer(&challenge, &generate_keypair());
    proof.nonce = [0; 32];
    assert!(matches!(
        challenges.verify(challenge, &proof, Purpose::Fetch),
        Err(CoreError::Denied)
    ));
}

#[test]
fn an_answer_to_a_different_challenge_is_denied() {
    let (_clock, challenges) = setup();
    let key = generate_keypair();
    let id = FileId::random();
    let first = challenges.issue(id, Purpose::Fetch);
    let second = challenges.issue(id, Purpose::Fetch);
    let proof = SignedRequest::answer(&first, &key);
    assert!(matches!(
        challenges.verify(second, &proof, Purpose::Fetch),
        Err(CoreError::Denied)
    ));
}

#[test]
fn an_answer_is_accepted_until_the_challenge_expires() {
    let (clock, challenges) = setup();
    let key = generate_keypair();
    let challenge = challenges.issue(FileId::random(), Purpose::Fetch);
    let proof = SignedRequest::answer(&challenge, &key);
    clock.advance(CHALLENGE_TTL_SECS - 1);
    assert!(challenges.verify(challenge, &proof, Purpose::Fetch).is_ok());
}

#[test]
fn an_answer_at_the_expiry_time_is_denied() {
    let (clock, challenges) = setup();
    let key = generate_keypair();
    let challenge = challenges.issue(FileId::random(), Purpose::Fetch);
    let proof = SignedRequest::answer(&challenge, &key);
    clock.advance(CHALLENGE_TTL_SECS);
    assert!(matches!(
        challenges.verify(challenge, &proof, Purpose::Fetch),
        Err(CoreError::Denied)
    ));
}

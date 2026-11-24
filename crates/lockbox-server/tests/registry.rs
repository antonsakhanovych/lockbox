mod common;

use std::sync::Arc;

use common::TestClock;
use lockbox_protocol::crypto::envelope::Envelope;
use lockbox_protocol::crypto::keys::generate_keypair;
use lockbox_protocol::crypto::{SigningKey, VerifyingKey};
use lockbox_protocol::message::MAX_LIFETIME_SECS;
use lockbox_protocol::{FileHeader, FileId, SignedRequest};
use lockbox_server::core::error::CoreError;
use lockbox_server::core::services::{
    Challenges, ForDelete, ForFetch, ForUpload, Intent, Registry, Verified,
};

const START: u64 = 1_000_000;

struct World {
    clock: Arc<TestClock>,
    challenges: Challenges<TestClock>,
    registry: Registry<TestClock>,
}

fn world() -> World {
    let clock = TestClock::at(START);
    World {
        challenges: Challenges::new(clock.clone()),
        registry: Registry::new(clock.clone()),
        clock,
    }
}

impl World {
    fn verified<I>(&self, id: FileId, key: &SigningKey) -> Verified<I>
    where
        I: Intent,
    {
        let challenge = self.challenges.issue(id, I::PURPOSE);
        let proof = SignedRequest::answer(&challenge, key);
        self.challenges.verify(challenge, &proof).unwrap()
    }

    fn upload(&self, owner: &SigningKey, recipients: &[VerifyingKey], lifetime: u64) -> FileId {
        let id = FileId::random();
        let who = self.verified::<ForUpload>(id, owner);
        self.registry
            .register(&who, header(recipients, START + lifetime))
            .unwrap();
        id
    }
}

fn header(recipients: &[VerifyingKey], expires_at: u64) -> FileHeader {
    let (envelope, ciphertext) = Envelope::encrypt_to_recipients(b"hello", recipients)
        .unwrap()
        .into_parts();
    FileHeader {
        envelope,
        ciphertext_len: ciphertext.len() as u64,
        expires_at,
    }
}

fn denied<T: std::fmt::Debug>(result: Result<T, CoreError>) -> bool {
    matches!(result, Err(CoreError::Denied))
}

#[test]
fn registering_returns_the_requested_expiry_when_it_is_within_the_limit() {
    let w = world();
    let owner = generate_keypair();
    let id = FileId::random();
    let who = w.verified::<ForUpload>(id, &owner);
    let granted = w
        .registry
        .register(&who, header(&[owner.verifying_key()], START + 120))
        .unwrap();
    assert_eq!(granted, START + 120);
}

#[test]
fn registering_clamps_the_expiry_to_the_maximum_lifetime() {
    let w = world();
    let owner = generate_keypair();
    let id = FileId::random();
    let who = w.verified::<ForUpload>(id, &owner);
    let granted = w
        .registry
        .register(&who, header(&[owner.verifying_key()], START + 10_000))
        .unwrap();
    assert_eq!(granted, START + MAX_LIFETIME_SECS);
}

#[test]
fn the_clamped_expiry_is_what_recipients_see() {
    let w = world();
    let owner = generate_keypair();
    let recipient = generate_keypair();
    let id = FileId::random();
    let who = w.verified::<ForUpload>(id, &owner);
    w.registry
        .register(&who, header(&[recipient.verifying_key()], START + 10_000))
        .unwrap();
    let fetch = w.verified::<ForFetch>(id, &recipient);
    let granted = w.registry.fetch_header(&fetch).unwrap();
    assert_eq!(granted.expires_at, START + MAX_LIFETIME_SECS);
}

#[test]
fn registering_an_expiry_that_is_not_in_the_future_is_denied() {
    let w = world();
    let owner = generate_keypair();
    let who = w.verified::<ForUpload>(FileId::random(), &owner);
    assert!(denied(
        w.registry
            .register(&who, header(&[owner.verifying_key()], START))
    ));
}

#[test]
fn registering_an_invalid_header_is_denied() {
    let w = world();
    let owner = generate_keypair();
    let who = w.verified::<ForUpload>(FileId::random(), &owner);
    let mut bad = header(&[owner.verifying_key()], START + 60);
    bad.ciphertext_len = 0;
    assert!(denied(w.registry.register(&who, bad)));
}

#[test]
fn registering_the_same_file_id_twice_is_denied() {
    let w = world();
    let owner = generate_keypair();
    let id = FileId::random();
    let first = w.verified::<ForUpload>(id, &owner);
    let second = w.verified::<ForUpload>(id, &owner);
    let h = header(&[owner.verifying_key()], START + 60);
    w.registry.register(&first, h.clone()).unwrap();
    assert!(denied(w.registry.register(&second, h)));
}

#[test]
fn a_listed_recipient_may_fetch() {
    let w = world();
    let owner = generate_keypair();
    let recipient = generate_keypair();
    let id = w.upload(&owner, &[recipient.verifying_key()], 60);
    let fetch = w.verified::<ForFetch>(id, &recipient);
    let granted = w.registry.fetch_header(&fetch).unwrap();
    assert_eq!(granted.recipient.recipient(), &recipient.verifying_key());
    assert_eq!(granted.expires_at, START + 60);
}

#[test]
fn every_listed_recipient_gets_their_own_header() {
    let w = world();
    let owner = generate_keypair();
    let first = generate_keypair();
    let second = generate_keypair();
    let id = w.upload(&owner, &[first.verifying_key(), second.verifying_key()], 60);
    for key in [&first, &second] {
        let fetch = w.verified::<ForFetch>(id, key);
        let granted = w.registry.fetch_header(&fetch).unwrap();
        assert_eq!(granted.recipient.recipient(), &key.verifying_key());
    }
}

#[test]
fn a_key_that_is_not_listed_may_not_fetch() {
    let w = world();
    let owner = generate_keypair();
    let recipient = generate_keypair();
    let id = w.upload(&owner, &[recipient.verifying_key()], 60);
    let stranger = w.verified::<ForFetch>(id, &generate_keypair());
    assert!(denied(w.registry.fetch_header(&stranger)));
}

#[test]
fn the_owner_may_not_fetch_unless_listed() {
    let w = world();
    let owner = generate_keypair();
    let recipient = generate_keypair();
    let id = w.upload(&owner, &[recipient.verifying_key()], 60);
    let fetch = w.verified::<ForFetch>(id, &owner);
    assert!(denied(w.registry.fetch_header(&fetch)));
}

#[test]
fn fetching_an_unknown_file_is_denied() {
    let w = world();
    let key = generate_keypair();
    let fetch = w.verified::<ForFetch>(FileId::random(), &key);
    assert!(denied(w.registry.fetch_header(&fetch)));
}

#[test]
fn fetching_is_denied_once_the_file_has_expired() {
    let w = world();
    let owner = generate_keypair();
    let recipient = generate_keypair();
    let id = w.upload(&owner, &[recipient.verifying_key()], 60);
    w.clock.advance(60);
    let fetch = w.verified::<ForFetch>(id, &recipient);
    assert!(denied(w.registry.fetch_header(&fetch)));
}

#[test]
fn fetching_still_works_just_before_expiry() {
    let w = world();
    let owner = generate_keypair();
    let recipient = generate_keypair();
    let id = w.upload(&owner, &[recipient.verifying_key()], 60);
    w.clock.advance(59);
    let fetch = w.verified::<ForFetch>(id, &recipient);
    assert!(w.registry.fetch_header(&fetch).is_ok());
}

#[test]
fn fetching_can_be_repeated() {
    let w = world();
    let owner = generate_keypair();
    let recipient = generate_keypair();
    let id = w.upload(&owner, &[recipient.verifying_key()], 60);
    for _ in 0..2 {
        let fetch = w.verified::<ForFetch>(id, &recipient);
        assert!(w.registry.fetch_header(&fetch).is_ok());
    }
}

#[test]
fn the_owner_may_delete() {
    let w = world();
    let owner = generate_keypair();
    let id = w.upload(&owner, &[owner.verifying_key()], 60);
    let delete = w.verified::<ForDelete>(id, &owner);
    assert!(w.registry.delete(&delete).is_ok());
}

#[test]
fn a_deleted_file_can_no_longer_be_fetched() {
    let w = world();
    let owner = generate_keypair();
    let id = w.upload(&owner, &[owner.verifying_key()], 60);
    let delete = w.verified::<ForDelete>(id, &owner);
    w.registry.delete(&delete).unwrap();
    let fetch = w.verified::<ForFetch>(id, &owner);
    assert!(denied(w.registry.fetch_header(&fetch)));
}

#[test]
fn deleting_twice_is_denied() {
    let w = world();
    let owner = generate_keypair();
    let id = w.upload(&owner, &[owner.verifying_key()], 60);
    let first = w.verified::<ForDelete>(id, &owner);
    let second = w.verified::<ForDelete>(id, &owner);
    w.registry.delete(&first).unwrap();
    assert!(denied(w.registry.delete(&second)));
}

#[test]
fn a_recipient_may_not_delete() {
    let w = world();
    let owner = generate_keypair();
    let recipient = generate_keypair();
    let id = w.upload(&owner, &[recipient.verifying_key()], 60);
    let delete = w.verified::<ForDelete>(id, &recipient);
    assert!(denied(w.registry.delete(&delete)));
}

#[test]
fn a_refused_delete_leaves_the_file_in_place() {
    let w = world();
    let owner = generate_keypair();
    let recipient = generate_keypair();
    let id = w.upload(&owner, &[recipient.verifying_key()], 60);
    let delete = w.verified::<ForDelete>(id, &recipient);
    let _ = w.registry.delete(&delete);
    let fetch = w.verified::<ForFetch>(id, &recipient);
    assert!(w.registry.fetch_header(&fetch).is_ok());
}

#[test]
fn deleting_an_unknown_file_is_denied() {
    let w = world();
    let key = generate_keypair();
    let delete = w.verified::<ForDelete>(FileId::random(), &key);
    assert!(denied(w.registry.delete(&delete)));
}

#[test]
fn deleting_an_expired_file_is_denied() {
    let w = world();
    let owner = generate_keypair();
    let id = w.upload(&owner, &[owner.verifying_key()], 60);
    w.clock.advance(60);
    let delete = w.verified::<ForDelete>(id, &owner);
    assert!(denied(w.registry.delete(&delete)));
}

#[test]
fn files_do_not_affect_each_other() {
    let w = world();
    let owner = generate_keypair();
    let first = w.upload(&owner, &[owner.verifying_key()], 60);
    let second = w.upload(&owner, &[owner.verifying_key()], 60);
    let delete = w.verified::<ForDelete>(first, &owner);
    w.registry.delete(&delete).unwrap();
    let fetch = w.verified::<ForFetch>(second, &owner);
    assert!(w.registry.fetch_header(&fetch).is_ok());
}

#[tokio::test]
async fn the_registry_can_be_shared_between_tasks() {
    let w = Arc::new(world());
    let owner = generate_keypair();
    let handles: Vec<_> = (0..16)
        .map(|_| {
            let w = w.clone();
            let key = owner.clone();
            tokio::spawn(async move { w.upload(&key, &[key.verifying_key()], 60) })
        })
        .collect();
    for handle in handles {
        let id = handle.await.unwrap();
        let fetch = w.verified::<ForFetch>(id, &owner);
        assert!(w.registry.fetch_header(&fetch).is_ok());
    }
}

#[test]
fn a_file_is_expired_exactly_when_its_time_comes() {
    let w = world();
    let owner = generate_keypair();
    let id = w.upload(&owner, &[owner.verifying_key()], 60);
    w.clock.advance(59);
    assert!(!w.registry.expire(id));
    w.clock.advance(1);
    assert!(w.registry.expire(id));
}

#[test]
fn expiring_removes_the_record() {
    let w = world();
    let owner = generate_keypair();
    let id = w.upload(&owner, &[owner.verifying_key()], 60);
    w.clock.advance(60);
    w.registry.expire(id);
    assert!(!w.registry.expire(id));
}

#[test]
fn a_file_that_has_not_expired_is_kept() {
    let w = world();
    let owner = generate_keypair();
    let id = w.upload(&owner, &[owner.verifying_key()], 60);
    assert!(!w.registry.expire(id));
    let fetch = w.verified::<ForFetch>(id, &owner);
    assert!(w.registry.fetch_header(&fetch).is_ok());
}

#[test]
fn expiring_an_unknown_file_does_nothing() {
    let w = world();
    assert!(!w.registry.expire(FileId::random()));
}

#[test]
fn expiring_a_deleted_file_does_nothing() {
    let w = world();
    let owner = generate_keypair();
    let id = w.upload(&owner, &[owner.verifying_key()], 60);
    let delete = w.verified::<ForDelete>(id, &owner);
    w.registry.delete(&delete).unwrap();
    w.clock.advance(60);
    assert!(!w.registry.expire(id));
}

#[test]
fn expiring_one_file_leaves_the_others() {
    let w = world();
    let owner = generate_keypair();
    let short = w.upload(&owner, &[owner.verifying_key()], 60);
    let long = w.upload(&owner, &[owner.verifying_key()], 120);
    w.clock.advance(60);
    assert!(w.registry.expire(short));
    assert!(!w.registry.expire(long));
}

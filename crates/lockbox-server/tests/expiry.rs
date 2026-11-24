mod common;

use std::sync::Arc;

use common::TestClock;
use lockbox_protocol::crypto::envelope::Envelope;
use lockbox_protocol::crypto::keys::generate_keypair;
use lockbox_protocol::crypto::{SigningKey, VerifyingKey};
use lockbox_protocol::{FileHeader, FileId, SignedRequest};
use lockbox_server::adapters::driven::DiskStore;
use lockbox_server::core::ports::driven::{FileStore, StoreError};
use lockbox_server::core::services::{
    Challenges, Expiry, Fetches, ForDelete, ForFetch, ForUpload, Intent, Registry, Verified,
};
use tempfile::{TempDir, tempdir};
use tokio::io::AsyncWriteExt;

const START: u64 = 1_000_000;

struct World {
    _dir: TempDir,
    clock: Arc<TestClock>,
    challenges: Challenges<TestClock>,
    registry: Arc<Registry<TestClock>>,
    store: Arc<DiskStore>,
    expiry: Expiry<TestClock, DiskStore>,
    fetches: Fetches<TestClock, DiskStore>,
}

async fn world() -> World {
    let dir = tempdir().unwrap();
    let clock = TestClock::at(START);
    let store = Arc::new(DiskStore::new(dir.path().to_path_buf()).await.unwrap());
    let registry = Arc::new(Registry::new(clock.clone()));
    World {
        expiry: Expiry::new(registry.clone(), store.clone()),
        fetches: Fetches::new(registry.clone(), store.clone()),
        challenges: Challenges::new(clock.clone()),
        registry,
        store,
        clock,
        _dir: dir,
    }
}

fn prepare(recipients: &[VerifyingKey], lifetime: u64) -> (FileHeader, Vec<u8>) {
    let (envelope, ciphertext) = Envelope::encrypt_to_recipients(b"hello", recipients)
        .unwrap()
        .into_parts();
    let header = FileHeader {
        envelope,
        ciphertext_len: ciphertext.len() as u64,
        expires_at: START + lifetime,
    };
    (header, ciphertext)
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

    async fn put(&self, owner: &SigningKey, lifetime: u64) -> (FileId, Vec<u8>) {
        let (header, ciphertext) = prepare(&[owner.verifying_key()], lifetime);
        let id = FileId::random();
        let mut writer = self.store.create(id).await.unwrap();
        writer.write_all(&ciphertext).await.unwrap();
        writer.shutdown().await.unwrap();
        let who = self.verified::<ForUpload>(id, owner);
        self.registry.register(&who, header).unwrap();
        (id, ciphertext)
    }

    async fn stored(&self, id: FileId) -> bool {
        self.store.open(id).await.is_ok()
    }

    fn registered(&self, id: FileId, key: &SigningKey) -> bool {
        let who = self.verified::<ForFetch>(id, key);
        self.registry.fetch_header(&who).is_ok()
    }
}

#[tokio::test]
async fn an_expired_file_is_removed_from_the_store() {
    let w = world().await;
    let owner = generate_keypair();
    let (id, _) = w.put(&owner, 60).await;
    w.clock.advance(60);
    w.expiry.expire(id).await.unwrap();
    assert!(matches!(w.store.open(id).await, Err(StoreError::NotFound)));
}

#[tokio::test]
async fn an_expired_file_is_removed_from_the_registry() {
    let w = world().await;
    let owner = generate_keypair();
    let (id, _) = w.put(&owner, 60).await;
    w.clock.advance(60);
    w.expiry.expire(id).await.unwrap();
    assert!(!w.registry.expire(id));
}

#[tokio::test]
async fn a_file_that_has_not_expired_is_left_alone() {
    let w = world().await;
    let owner = generate_keypair();
    let (id, _) = w.put(&owner, 60).await;
    w.clock.advance(59);
    w.expiry.expire(id).await.unwrap();
    assert!(w.stored(id).await);
    assert!(w.registered(id, &owner));
}

#[tokio::test]
async fn expiring_an_unknown_file_is_fine() {
    let w = world().await;
    assert!(w.expiry.expire(FileId::random()).await.is_ok());
}

#[tokio::test]
async fn expiring_twice_is_fine() {
    let w = world().await;
    let owner = generate_keypair();
    let (id, _) = w.put(&owner, 60).await;
    w.clock.advance(60);
    w.expiry.expire(id).await.unwrap();
    assert!(w.expiry.expire(id).await.is_ok());
}

#[tokio::test]
async fn a_file_already_missing_from_the_store_is_still_expired() {
    let w = world().await;
    let owner = generate_keypair();
    let (id, _) = w.put(&owner, 60).await;
    w.store.remove(id).await.unwrap();
    w.clock.advance(60);
    assert!(w.expiry.expire(id).await.is_ok());
    assert!(!w.registry.expire(id));
}

#[tokio::test]
async fn a_file_deleted_earlier_is_not_touched_again() {
    let w = world().await;
    let owner = generate_keypair();
    let (id, _) = w.put(&owner, 60).await;
    let delete = w.verified::<ForDelete>(id, &owner);
    w.registry.delete(&delete).unwrap();
    w.store.remove(id).await.unwrap();
    w.clock.advance(60);
    assert!(w.expiry.expire(id).await.is_ok());
}

#[tokio::test]
async fn only_the_named_file_is_removed() {
    let w = world().await;
    let owner = generate_keypair();
    let (first, _) = w.put(&owner, 60).await;
    let (second, _) = w.put(&owner, 60).await;
    w.clock.advance(60);
    w.expiry.expire(first).await.unwrap();
    assert!(!w.stored(first).await);
    assert!(w.stored(second).await);
}

#[tokio::test]
async fn a_fetch_in_progress_finishes_after_the_file_expires() {
    let w = world().await;
    let owner = generate_keypair();
    let (id, ciphertext) = w.put(&owner, 60).await;
    let who = w.verified::<ForFetch>(id, &owner);
    let mut fetch = w.fetches.begin(who).await.unwrap();
    w.clock.advance(60);
    w.expiry.expire(id).await.unwrap();
    let mut bytes = Vec::new();
    while let Some(chunk) = fetch.next_chunk().await.unwrap() {
        bytes.extend_from_slice(chunk.as_bytes());
    }
    assert_eq!(bytes, ciphertext);
}

mod common;

use std::sync::Arc;

use common::TestClock;
use lockbox_protocol::crypto::envelope::Envelope;
use lockbox_protocol::crypto::keys::generate_keypair;
use lockbox_protocol::crypto::{SigningKey, VerifyingKey};
use lockbox_protocol::{FileHeader, FileId, Purpose, SignedRequest};
use lockbox_server::adapters::driven::DiskStore;
use lockbox_server::core::error::CoreError;
use lockbox_server::core::ports::driven::{FileStore, StoreError};
use lockbox_server::core::services::{Challenges, Deletes, Fetches, Registry, Verified};
use tempfile::{TempDir, tempdir};
use tokio::io::AsyncWriteExt;

const START: u64 = 1_000_000;

struct World {
    _dir: TempDir,
    clock: Arc<TestClock>,
    challenges: Challenges<TestClock>,
    registry: Arc<Registry<TestClock>>,
    store: Arc<DiskStore>,
    deletes: Deletes<TestClock, DiskStore>,
    fetches: Fetches<TestClock, DiskStore>,
}

async fn world() -> World {
    let dir = tempdir().unwrap();
    let clock = TestClock::at(START);
    let store = Arc::new(DiskStore::new(dir.path().to_path_buf()).await.unwrap());
    let registry = Arc::new(Registry::new(clock.clone()));
    World {
        deletes: Deletes::new(registry.clone(), store.clone()),
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
    fn verified(&self, id: FileId, purpose: Purpose, key: &SigningKey) -> Verified {
        let challenge = self.challenges.issue(id, purpose);
        let proof = SignedRequest::answer(&challenge, key);
        self.challenges.verify(challenge, &proof, purpose).unwrap()
    }

    async fn put(&self, owner: &SigningKey, recipients: &[VerifyingKey]) -> (FileId, Vec<u8>) {
        let (header, ciphertext) = prepare(recipients, 60);
        let id = FileId::random();
        let mut writer = self.store.create(id).await.unwrap();
        writer.write_all(&ciphertext).await.unwrap();
        writer.shutdown().await.unwrap();
        let who = self.verified(id, Purpose::Upload, owner);
        self.registry.register(&who, header).unwrap();
        (id, ciphertext)
    }

    async fn delete(&self, id: FileId, key: &SigningKey) -> Result<(), CoreError> {
        let who = self.verified(id, Purpose::Delete, key);
        self.deletes.delete(who).await
    }

    fn can_fetch(&self, id: FileId, key: &SigningKey) -> bool {
        let who = self.verified(id, Purpose::Fetch, key);
        self.registry.fetch_header(&who).is_ok()
    }
}

#[tokio::test]
async fn the_owner_can_delete() {
    let w = world().await;
    let owner = generate_keypair();
    let (id, _) = w.put(&owner, &[owner.verifying_key()]).await;
    assert!(w.delete(id, &owner).await.is_ok());
}

#[tokio::test]
async fn a_deleted_file_is_gone_from_the_store() {
    let w = world().await;
    let owner = generate_keypair();
    let (id, _) = w.put(&owner, &[owner.verifying_key()]).await;
    w.delete(id, &owner).await.unwrap();
    assert!(matches!(w.store.open(id).await, Err(StoreError::NotFound)));
}

#[tokio::test]
async fn a_deleted_file_can_no_longer_be_fetched() {
    let w = world().await;
    let owner = generate_keypair();
    let recipient = generate_keypair();
    let (id, _) = w.put(&owner, &[recipient.verifying_key()]).await;
    assert!(w.can_fetch(id, &recipient));
    w.delete(id, &owner).await.unwrap();
    assert!(!w.can_fetch(id, &recipient));
}

#[tokio::test]
async fn a_recipient_cannot_delete() {
    let w = world().await;
    let owner = generate_keypair();
    let recipient = generate_keypair();
    let (id, _) = w.put(&owner, &[recipient.verifying_key()]).await;
    assert!(matches!(
        w.delete(id, &recipient).await,
        Err(CoreError::Denied)
    ));
}

#[tokio::test]
async fn a_refused_delete_leaves_the_file_stored_and_fetchable() {
    let w = world().await;
    let owner = generate_keypair();
    let recipient = generate_keypair();
    let (id, _) = w.put(&owner, &[recipient.verifying_key()]).await;
    let _ = w.delete(id, &recipient).await;
    assert!(w.store.open(id).await.is_ok());
    assert!(w.can_fetch(id, &recipient));
}

#[tokio::test]
async fn a_stranger_cannot_delete() {
    let w = world().await;
    let owner = generate_keypair();
    let (id, _) = w.put(&owner, &[owner.verifying_key()]).await;
    assert!(matches!(
        w.delete(id, &generate_keypair()).await,
        Err(CoreError::Denied)
    ));
    assert!(w.store.open(id).await.is_ok());
}

#[tokio::test]
async fn deleting_an_unknown_file_is_denied() {
    let w = world().await;
    assert!(matches!(
        w.delete(FileId::random(), &generate_keypair()).await,
        Err(CoreError::Denied)
    ));
}

#[tokio::test]
async fn deleting_twice_is_denied() {
    let w = world().await;
    let owner = generate_keypair();
    let (id, _) = w.put(&owner, &[owner.verifying_key()]).await;
    w.delete(id, &owner).await.unwrap();
    assert!(matches!(w.delete(id, &owner).await, Err(CoreError::Denied)));
}

#[tokio::test]
async fn deleting_an_expired_file_is_denied() {
    let w = world().await;
    let owner = generate_keypair();
    let (id, _) = w.put(&owner, &[owner.verifying_key()]).await;
    w.clock.advance(60);
    assert!(matches!(w.delete(id, &owner).await, Err(CoreError::Denied)));
}

#[tokio::test]
async fn a_file_already_missing_from_the_store_still_counts_as_deleted() {
    let w = world().await;
    let owner = generate_keypair();
    let (id, _) = w.put(&owner, &[owner.verifying_key()]).await;
    w.store.remove(id).await.unwrap();
    assert!(w.delete(id, &owner).await.is_ok());
    assert!(!w.can_fetch(id, &owner));
}

#[tokio::test]
async fn other_files_are_not_affected() {
    let w = world().await;
    let owner = generate_keypair();
    let (first, _) = w.put(&owner, &[owner.verifying_key()]).await;
    let (second, _) = w.put(&owner, &[owner.verifying_key()]).await;
    w.delete(first, &owner).await.unwrap();
    assert!(w.store.open(second).await.is_ok());
    assert!(w.can_fetch(second, &owner));
}

#[tokio::test]
async fn a_fetch_in_progress_finishes_after_the_delete() {
    let w = world().await;
    let owner = generate_keypair();
    let (id, ciphertext) = w.put(&owner, &[owner.verifying_key()]).await;
    let who = w.verified(id, Purpose::Fetch, &owner);
    let mut fetch = w.fetches.begin(who).await.unwrap();
    w.delete(id, &owner).await.unwrap();
    let mut bytes = Vec::new();
    while let Some(chunk) = fetch.next_chunk().await.unwrap() {
        bytes.extend_from_slice(chunk.as_bytes());
    }
    assert_eq!(bytes, ciphertext);
}

#[tokio::test]
async fn deletes_can_run_on_separate_tasks() {
    let w = Arc::new(world().await);
    let owner = generate_keypair();
    let mut ids = Vec::new();
    for _ in 0..8 {
        ids.push(w.put(&owner, &[owner.verifying_key()]).await.0);
    }
    let handles: Vec<_> = ids
        .iter()
        .map(|&id| {
            let w = w.clone();
            let key = owner.clone();
            tokio::spawn(async move { w.delete(id, &key).await })
        })
        .collect();
    for handle in handles {
        handle.await.unwrap().unwrap();
    }
    for id in ids {
        assert!(matches!(w.store.open(id).await, Err(StoreError::NotFound)));
    }
}

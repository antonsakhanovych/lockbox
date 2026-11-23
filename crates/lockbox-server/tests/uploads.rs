mod common;

use std::sync::Arc;

use common::TestClock;
use lockbox_protocol::chunk::CHUNK_LEN;
use lockbox_protocol::crypto::envelope::Envelope;
use lockbox_protocol::crypto::keys::generate_keypair;
use lockbox_protocol::crypto::{SigningKey, VerifyingKey};
use lockbox_protocol::message::MAX_LIFETIME_SECS;
use lockbox_protocol::{Chunk, FileHeader, FileId, Purpose, SignedRequest};
use lockbox_server::adapters::driven::DiskStore;
use lockbox_server::core::error::CoreError;
use lockbox_server::core::ports::driven::{FileStore, StoreError};
use lockbox_server::core::services::{Challenges, Registry, Upload, Uploads, Verified};
use tempfile::{TempDir, tempdir};
use tokio::io::AsyncReadExt;

const START: u64 = 1_000_000;

struct World {
    _dir: TempDir,
    clock: Arc<TestClock>,
    challenges: Challenges<TestClock>,
    registry: Arc<Registry<TestClock>>,
    store: Arc<DiskStore>,
    uploads: Uploads<TestClock, DiskStore>,
}

async fn world() -> World {
    let dir = tempdir().unwrap();
    let clock = TestClock::at(START);
    let store = Arc::new(DiskStore::new(dir.path().to_path_buf()).await.unwrap());
    let registry = Arc::new(Registry::new(clock.clone()));
    World {
        uploads: Uploads::new(registry.clone(), store.clone()),
        challenges: Challenges::new(clock.clone()),
        registry,
        store,
        clock,
        _dir: dir,
    }
}

struct Prepared {
    header: FileHeader,
    ciphertext: Vec<u8>,
}

fn prepare(message: &[u8], recipients: &[VerifyingKey], lifetime: u64) -> Prepared {
    let (envelope, ciphertext) = Envelope::encrypt_to_recipients(message, recipients)
        .unwrap()
        .into_parts();
    Prepared {
        header: FileHeader {
            envelope,
            ciphertext_len: ciphertext.len() as u64,
            expires_at: START + lifetime,
        },
        ciphertext,
    }
}

fn chunks(bytes: &[u8], size: usize) -> Vec<Chunk> {
    bytes
        .chunks(size)
        .map(|piece| Chunk::new(piece.to_vec()).unwrap())
        .collect()
}

impl World {
    fn verified(&self, id: FileId, purpose: Purpose, key: &SigningKey) -> Verified {
        let challenge = self.challenges.issue(id, purpose);
        let proof = SignedRequest::answer(&challenge, key);
        self.challenges.verify(challenge, &proof, purpose).unwrap()
    }

    async fn begin(
        &self,
        owner: &SigningKey,
        header: FileHeader,
    ) -> Result<Upload<TestClock, DiskStore>, CoreError> {
        let who = self.verified(FileId::random(), Purpose::Upload, owner);
        self.uploads.begin(who, header).await
    }

    async fn send_all(
        &self,
        owner: &SigningKey,
        prepared: &Prepared,
        size: usize,
    ) -> (FileId, u64) {
        let mut upload = self.begin(owner, prepared.header.clone()).await.unwrap();
        for chunk in chunks(&prepared.ciphertext, size) {
            upload.write(&chunk).await.unwrap();
        }
        let id = upload.file_id();
        (id, upload.finish().await.unwrap())
    }

    async fn stored(&self, id: FileId) -> Vec<u8> {
        let mut reader = self.store.open(id).await.unwrap();
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).await.unwrap();
        bytes
    }
}

fn message(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

#[tokio::test]
async fn an_upload_is_stored_byte_for_byte() {
    let w = world().await;
    let owner = generate_keypair();
    let prepared = prepare(&message(1000), &[owner.verifying_key()], 60);
    let (id, _) = w.send_all(&owner, &prepared, 100).await;
    assert_eq!(w.stored(id).await, prepared.ciphertext);
}

#[tokio::test]
async fn a_file_larger_than_one_chunk_is_stored_whole() {
    let w = world().await;
    let owner = generate_keypair();
    let prepared = prepare(&message(CHUNK_LEN * 2 + 17), &[owner.verifying_key()], 60);
    let (id, _) = w.send_all(&owner, &prepared, CHUNK_LEN).await;
    assert_eq!(w.stored(id).await, prepared.ciphertext);
}

#[tokio::test]
async fn finishing_returns_the_granted_expiry() {
    let w = world().await;
    let owner = generate_keypair();
    let prepared = prepare(&message(10), &[owner.verifying_key()], 120);
    let (_, expires_at) = w.send_all(&owner, &prepared, 64).await;
    assert_eq!(expires_at, START + 120);
}

#[tokio::test]
async fn an_expiry_beyond_the_maximum_is_clamped() {
    let w = world().await;
    let owner = generate_keypair();
    let prepared = prepare(&message(10), &[owner.verifying_key()], 10_000);
    let (_, expires_at) = w.send_all(&owner, &prepared, 64).await;
    assert_eq!(expires_at, START + MAX_LIFETIME_SECS);
}

#[tokio::test]
async fn a_finished_upload_can_be_fetched_by_a_recipient() {
    let w = world().await;
    let owner = generate_keypair();
    let recipient = generate_keypair();
    let prepared = prepare(&message(10), &[recipient.verifying_key()], 60);
    let (id, _) = w.send_all(&owner, &prepared, 64).await;
    let fetch = w.verified(id, Purpose::Fetch, &recipient);
    assert!(w.registry.fetch_header(&fetch).is_ok());
}

#[tokio::test]
async fn a_finished_upload_can_be_deleted_by_the_owner() {
    let w = world().await;
    let owner = generate_keypair();
    let prepared = prepare(&message(10), &[owner.verifying_key()], 60);
    let (id, _) = w.send_all(&owner, &prepared, 64).await;
    let delete = w.verified(id, Purpose::Delete, &owner);
    assert!(w.registry.delete(&delete).is_ok());
}

#[tokio::test]
async fn remaining_counts_down_as_chunks_arrive() {
    let w = world().await;
    let owner = generate_keypair();
    let prepared = prepare(&message(300), &[owner.verifying_key()], 60);
    let total = prepared.ciphertext.len() as u64;
    let mut upload = w.begin(&owner, prepared.header.clone()).await.unwrap();
    assert_eq!(upload.remaining(), total);
    let first = Chunk::new(prepared.ciphertext[..100].to_vec()).unwrap();
    upload.write(&first).await.unwrap();
    assert_eq!(upload.remaining(), total - 100);
}

#[tokio::test]
async fn the_file_id_is_the_one_the_challenge_was_for() {
    let w = world().await;
    let owner = generate_keypair();
    let id = FileId::random();
    let who = w.verified(id, Purpose::Upload, &owner);
    let prepared = prepare(&message(10), &[owner.verifying_key()], 60);
    let upload = w.uploads.begin(who, prepared.header).await.unwrap();
    assert_eq!(upload.file_id(), id);
}

#[tokio::test]
async fn an_invalid_header_is_rejected_before_anything_is_stored() {
    let w = world().await;
    let owner = generate_keypair();
    let mut prepared = prepare(&message(10), &[owner.verifying_key()], 60);
    prepared.header.ciphertext_len = 0;
    let id = FileId::random();
    let who = w.verified(id, Purpose::Upload, &owner);
    let result = w.uploads.begin(who, prepared.header).await;
    assert!(matches!(result, Err(CoreError::Invalid)));
    assert!(matches!(w.store.open(id).await, Err(StoreError::NotFound)));
}

#[tokio::test]
async fn an_empty_chunk_is_invalid() {
    let w = world().await;
    let owner = generate_keypair();
    let prepared = prepare(&message(10), &[owner.verifying_key()], 60);
    let mut upload = w.begin(&owner, prepared.header).await.unwrap();
    let empty = Chunk::new(Vec::new()).unwrap();
    assert!(matches!(
        upload.write(&empty).await,
        Err(CoreError::Invalid)
    ));
}

#[tokio::test]
async fn a_chunk_larger_than_what_remains_is_invalid() {
    let w = world().await;
    let owner = generate_keypair();
    let prepared = prepare(&message(10), &[owner.verifying_key()], 60);
    let total = prepared.ciphertext.len();
    let mut upload = w.begin(&owner, prepared.header).await.unwrap();
    let too_big = Chunk::new(vec![0; total + 1]).unwrap();
    assert!(matches!(
        upload.write(&too_big).await,
        Err(CoreError::Invalid)
    ));
}

#[tokio::test]
async fn a_chunk_after_the_last_one_is_invalid() {
    let w = world().await;
    let owner = generate_keypair();
    let prepared = prepare(&message(10), &[owner.verifying_key()], 60);
    let mut upload = w.begin(&owner, prepared.header.clone()).await.unwrap();
    for chunk in chunks(&prepared.ciphertext, 64) {
        upload.write(&chunk).await.unwrap();
    }
    let extra = Chunk::new(vec![1]).unwrap();
    assert!(matches!(
        upload.write(&extra).await,
        Err(CoreError::Invalid)
    ));
}

#[tokio::test]
async fn finishing_before_all_bytes_arrived_is_invalid() {
    let w = world().await;
    let owner = generate_keypair();
    let prepared = prepare(&message(300), &[owner.verifying_key()], 60);
    let mut upload = w.begin(&owner, prepared.header).await.unwrap();
    let id = upload.file_id();
    let part = Chunk::new(prepared.ciphertext[..100].to_vec()).unwrap();
    upload.write(&part).await.unwrap();
    assert!(matches!(upload.finish().await, Err(CoreError::Invalid)));
    assert!(matches!(w.store.open(id).await, Err(StoreError::NotFound)));
}

#[tokio::test]
async fn dropping_an_unfinished_upload_removes_its_partial_file() {
    let w = world().await;
    let owner = generate_keypair();
    let prepared = prepare(&message(300), &[owner.verifying_key()], 60);
    let mut upload = w.begin(&owner, prepared.header).await.unwrap();
    let id = upload.file_id();
    let part = Chunk::new(prepared.ciphertext[..100].to_vec()).unwrap();
    upload.write(&part).await.unwrap();
    drop(upload);
    assert!(matches!(w.store.open(id).await, Err(StoreError::NotFound)));
}

#[tokio::test]
async fn an_abandoned_upload_is_never_registered() {
    let w = world().await;
    let owner = generate_keypair();
    let recipient = generate_keypair();
    let prepared = prepare(&message(300), &[recipient.verifying_key()], 60);
    let mut upload = w.begin(&owner, prepared.header).await.unwrap();
    let id = upload.file_id();
    let part = Chunk::new(prepared.ciphertext[..100].to_vec()).unwrap();
    upload.write(&part).await.unwrap();
    drop(upload);
    let fetch = w.verified(id, Purpose::Fetch, &recipient);
    assert!(matches!(
        w.registry.fetch_header(&fetch),
        Err(CoreError::Denied)
    ));
}

#[tokio::test]
async fn a_file_is_not_registered_until_the_upload_finishes() {
    let w = world().await;
    let owner = generate_keypair();
    let prepared = prepare(&message(300), &[owner.verifying_key()], 60);
    let mut upload = w.begin(&owner, prepared.header.clone()).await.unwrap();
    let id = upload.file_id();
    for chunk in chunks(&prepared.ciphertext, 64) {
        upload.write(&chunk).await.unwrap();
    }
    let fetch = w.verified(id, Purpose::Fetch, &owner);
    assert!(w.registry.fetch_header(&fetch).is_err());
    upload.finish().await.unwrap();
    let fetch = w.verified(id, Purpose::Fetch, &owner);
    assert!(w.registry.fetch_header(&fetch).is_ok());
}

#[tokio::test]
async fn a_header_that_expires_during_the_upload_is_denied_and_removed() {
    let w = world().await;
    let owner = generate_keypair();
    let prepared = prepare(&message(300), &[owner.verifying_key()], 30);
    let mut upload = w.begin(&owner, prepared.header.clone()).await.unwrap();
    let id = upload.file_id();
    for chunk in chunks(&prepared.ciphertext, 64) {
        upload.write(&chunk).await.unwrap();
    }
    w.clock.advance(30);
    assert!(matches!(upload.finish().await, Err(CoreError::Denied)));
    assert!(matches!(w.store.open(id).await, Err(StoreError::NotFound)));
}

#[tokio::test]
async fn uploads_do_not_interfere_with_each_other() {
    let w = world().await;
    let owner = generate_keypair();
    let first = prepare(&message(500), &[owner.verifying_key()], 60);
    let second = prepare(&message(700), &[owner.verifying_key()], 60);
    let mut a = w.begin(&owner, first.header.clone()).await.unwrap();
    let mut b = w.begin(&owner, second.header.clone()).await.unwrap();
    let (id_a, id_b) = (a.file_id(), b.file_id());
    let a_chunks = chunks(&first.ciphertext, 64);
    let b_chunks = chunks(&second.ciphertext, 64);
    for i in 0..a_chunks.len().max(b_chunks.len()) {
        if let Some(chunk) = a_chunks.get(i) {
            a.write(chunk).await.unwrap();
        }
        if let Some(chunk) = b_chunks.get(i) {
            b.write(chunk).await.unwrap();
        }
    }
    a.finish().await.unwrap();
    b.finish().await.unwrap();
    assert_eq!(w.stored(id_a).await, first.ciphertext);
    assert_eq!(w.stored(id_b).await, second.ciphertext);
}

#[tokio::test]
async fn uploads_can_run_on_separate_tasks() {
    let w = Arc::new(world().await);
    let owner = generate_keypair();
    let handles: Vec<_> = (0..8)
        .map(|n| {
            let w = w.clone();
            let key = owner.clone();
            tokio::spawn(async move {
                let prepared = prepare(&message(200 + n), &[key.verifying_key()], 60);
                let (id, _) = w.send_all(&key, &prepared, 50).await;
                (id, prepared.ciphertext)
            })
        })
        .collect();
    for handle in handles {
        let (id, expected) = handle.await.unwrap();
        assert_eq!(w.stored(id).await, expected);
    }
}

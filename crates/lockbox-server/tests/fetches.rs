mod common;

use std::sync::Arc;

use common::TestClock;
use lockbox_protocol::chunk::CHUNK_LEN;
use lockbox_protocol::crypto::envelope::Envelope;
use lockbox_protocol::crypto::keys::generate_keypair;
use lockbox_protocol::crypto::{SigningKey, VerifyingKey};
use lockbox_protocol::{FileHeader, FileId, SignedRequest};
use lockbox_server::adapters::driven::DiskStore;
use lockbox_server::core::error::CoreError;
use lockbox_server::core::ports::driven::{FileStore, StoreError};
use lockbox_server::core::services::{
    Challenges, Fetch, Fetches, ForDelete, ForFetch, ForUpload, Intent, Registry, Verified,
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
    fetches: Fetches<TestClock, DiskStore>,
}

async fn world() -> World {
    let dir = tempdir().unwrap();
    let clock = TestClock::at(START);
    let store = Arc::new(DiskStore::new(dir.path().to_path_buf()).await.unwrap());
    let registry = Arc::new(Registry::new(clock.clone()));
    World {
        fetches: Fetches::new(registry.clone(), store.clone()),
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

fn message(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
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

    async fn publish(&self, owner: &SigningKey, prepared: &Prepared, stored: &[u8]) -> FileId {
        let id = FileId::random();
        let mut writer = self.store.create(id).await.unwrap();
        writer.write_all(stored).await.unwrap();
        writer.shutdown().await.unwrap();
        let who = self.verified::<ForUpload>(id, owner);
        self.registry
            .register(&who, prepared.header.clone())
            .unwrap();
        id
    }

    async fn put(&self, owner: &SigningKey, prepared: &Prepared) -> FileId {
        self.publish(owner, prepared, &prepared.ciphertext).await
    }

    async fn begin(
        &self,
        id: FileId,
        key: &SigningKey,
    ) -> Result<Fetch<<DiskStore as FileStore>::Reader>, CoreError> {
        let who = self.verified::<ForFetch>(id, key);
        self.fetches.begin(who).await
    }
}

async fn drain<R>(fetch: &mut Fetch<R>) -> Vec<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut chunks = Vec::new();
    while let Some(chunk) = fetch.next_chunk().await.unwrap() {
        chunks.push(chunk.into_bytes());
    }
    chunks
}

#[tokio::test]
async fn a_recipient_receives_the_stored_bytes() {
    let w = world().await;
    let owner = generate_keypair();
    let recipient = generate_keypair();
    let prepared = prepare(&message(1000), &[recipient.verifying_key()], 60);
    let id = w.put(&owner, &prepared).await;
    let mut fetch = w.begin(id, &recipient).await.unwrap();
    let bytes: Vec<u8> = drain(&mut fetch).await.concat();
    assert_eq!(bytes, prepared.ciphertext);
}

#[tokio::test]
async fn the_header_is_the_one_for_the_requester() {
    let w = world().await;
    let owner = generate_keypair();
    let recipient = generate_keypair();
    let prepared = prepare(&message(100), &[recipient.verifying_key()], 60);
    let id = w.put(&owner, &prepared).await;
    let fetch = w.begin(id, &recipient).await.unwrap();
    let header = fetch.header();
    assert_eq!(header.recipient.recipient(), &recipient.verifying_key());
    assert_eq!(header.ciphertext_len, prepared.ciphertext.len() as u64);
    assert_eq!(header.expires_at, START + 60);
}

#[tokio::test]
async fn a_large_file_comes_in_full_chunks_and_a_shorter_last_one() {
    let w = world().await;
    let owner = generate_keypair();
    let prepared = prepare(&message(CHUNK_LEN * 2 + 17), &[owner.verifying_key()], 60);
    let id = w.put(&owner, &prepared).await;
    let mut fetch = w.begin(id, &owner).await.unwrap();
    let chunks = drain(&mut fetch).await;
    assert_eq!(chunks.len(), 3);
    assert_eq!(chunks[0].len(), CHUNK_LEN);
    assert_eq!(chunks[1].len(), CHUNK_LEN);
    assert!(!chunks[2].is_empty() && chunks[2].len() <= CHUNK_LEN);
    assert_eq!(chunks.concat(), prepared.ciphertext);
}

#[tokio::test]
async fn a_file_that_is_an_exact_multiple_of_the_chunk_size_has_no_empty_chunk() {
    let w = world().await;
    let owner = generate_keypair();
    let overhead = prepare(b"", &[owner.verifying_key()], 60).ciphertext.len();
    let prepared = prepare(
        &message(CHUNK_LEN * 2 - overhead),
        &[owner.verifying_key()],
        60,
    );
    assert_eq!(prepared.ciphertext.len(), CHUNK_LEN * 2);
    let id = w.put(&owner, &prepared).await;
    let mut fetch = w.begin(id, &owner).await.unwrap();
    let chunks = drain(&mut fetch).await;
    assert_eq!(chunks.len(), 2);
    assert!(chunks.iter().all(|chunk| chunk.len() == CHUNK_LEN));
}

#[tokio::test]
async fn after_the_last_chunk_there_is_only_none() {
    let w = world().await;
    let owner = generate_keypair();
    let prepared = prepare(&message(10), &[owner.verifying_key()], 60);
    let id = w.put(&owner, &prepared).await;
    let mut fetch = w.begin(id, &owner).await.unwrap();
    drain(&mut fetch).await;
    assert!(fetch.next_chunk().await.unwrap().is_none());
    assert!(fetch.next_chunk().await.unwrap().is_none());
}

#[tokio::test]
async fn remaining_counts_down_to_zero() {
    let w = world().await;
    let owner = generate_keypair();
    let prepared = prepare(&message(CHUNK_LEN + 5), &[owner.verifying_key()], 60);
    let total = prepared.ciphertext.len() as u64;
    let id = w.put(&owner, &prepared).await;
    let mut fetch = w.begin(id, &owner).await.unwrap();
    assert_eq!(fetch.remaining(), total);
    fetch.next_chunk().await.unwrap();
    assert_eq!(fetch.remaining(), total - CHUNK_LEN as u64);
    drain(&mut fetch).await;
    assert_eq!(fetch.remaining(), 0);
}

#[tokio::test]
async fn a_file_can_be_fetched_more_than_once() {
    let w = world().await;
    let owner = generate_keypair();
    let recipient = generate_keypair();
    let prepared = prepare(&message(300), &[recipient.verifying_key()], 60);
    let id = w.put(&owner, &prepared).await;
    for _ in 0..2 {
        let mut fetch = w.begin(id, &recipient).await.unwrap();
        assert_eq!(drain(&mut fetch).await.concat(), prepared.ciphertext);
    }
}

#[tokio::test]
async fn every_recipient_gets_their_own_header_and_the_same_bytes() {
    let w = world().await;
    let owner = generate_keypair();
    let first = generate_keypair();
    let second = generate_keypair();
    let prepared = prepare(
        &message(300),
        &[first.verifying_key(), second.verifying_key()],
        60,
    );
    let id = w.put(&owner, &prepared).await;
    for key in [&first, &second] {
        let mut fetch = w.begin(id, key).await.unwrap();
        assert_eq!(fetch.header().recipient.recipient(), &key.verifying_key());
        assert_eq!(drain(&mut fetch).await.concat(), prepared.ciphertext);
    }
}

#[tokio::test]
async fn a_key_that_is_not_listed_is_denied() {
    let w = world().await;
    let owner = generate_keypair();
    let recipient = generate_keypair();
    let prepared = prepare(&message(10), &[recipient.verifying_key()], 60);
    let id = w.put(&owner, &prepared).await;
    assert!(matches!(
        w.begin(id, &generate_keypair()).await,
        Err(CoreError::Denied)
    ));
}

#[tokio::test]
async fn an_unknown_file_is_denied() {
    let w = world().await;
    assert!(matches!(
        w.begin(FileId::random(), &generate_keypair()).await,
        Err(CoreError::Denied)
    ));
}

#[tokio::test]
async fn an_expired_file_is_denied() {
    let w = world().await;
    let owner = generate_keypair();
    let prepared = prepare(&message(10), &[owner.verifying_key()], 60);
    let id = w.put(&owner, &prepared).await;
    w.clock.advance(60);
    assert!(matches!(w.begin(id, &owner).await, Err(CoreError::Denied)));
}

#[tokio::test]
async fn a_deleted_file_is_denied() {
    let w = world().await;
    let owner = generate_keypair();
    let prepared = prepare(&message(10), &[owner.verifying_key()], 60);
    let id = w.put(&owner, &prepared).await;
    let delete = w.verified::<ForDelete>(id, &owner);
    w.registry.delete(&delete).unwrap();
    w.store.remove(id).await.unwrap();
    assert!(matches!(w.begin(id, &owner).await, Err(CoreError::Denied)));
}

#[tokio::test]
async fn a_registered_file_missing_from_the_store_is_denied() {
    let w = world().await;
    let owner = generate_keypair();
    let prepared = prepare(&message(10), &[owner.verifying_key()], 60);
    let id = w.put(&owner, &prepared).await;
    w.store.remove(id).await.unwrap();
    assert!(matches!(w.begin(id, &owner).await, Err(CoreError::Denied)));
}

#[tokio::test]
async fn a_fetch_in_progress_survives_the_file_being_deleted() {
    let w = world().await;
    let owner = generate_keypair();
    let prepared = prepare(&message(CHUNK_LEN * 2), &[owner.verifying_key()], 60);
    let id = w.put(&owner, &prepared).await;
    let mut fetch = w.begin(id, &owner).await.unwrap();
    fetch.next_chunk().await.unwrap();
    let delete = w.verified::<ForDelete>(id, &owner);
    w.registry.delete(&delete).unwrap();
    w.store.remove(id).await.unwrap();
    let rest = drain(&mut fetch).await.concat();
    assert_eq!(rest, prepared.ciphertext[CHUNK_LEN..]);
}

#[tokio::test]
async fn a_file_shorter_than_its_header_is_a_store_error() {
    let w = world().await;
    let owner = generate_keypair();
    let prepared = prepare(&message(300), &[owner.verifying_key()], 60);
    let half = prepared.ciphertext.len() / 2;
    let id = w
        .publish(&owner, &prepared, &prepared.ciphertext[..half])
        .await;
    let mut fetch = w.begin(id, &owner).await.unwrap();
    assert!(matches!(
        fetch.next_chunk().await,
        Err(CoreError::Store(StoreError::Io(_)))
    ));
}

#[tokio::test]
async fn fetches_can_run_on_separate_tasks() {
    let w = Arc::new(world().await);
    let owner = generate_keypair();
    let prepared = Arc::new(prepare(&message(5000), &[owner.verifying_key()], 60));
    let id = w.put(&owner, &prepared).await;
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let w = w.clone();
            let key = owner.clone();
            let prepared = prepared.clone();
            tokio::spawn(async move {
                let mut fetch = w.begin(id, &key).await.unwrap();
                assert_eq!(drain(&mut fetch).await.concat(), prepared.ciphertext);
            })
        })
        .collect();
    for handle in handles {
        handle.await.unwrap();
    }
}

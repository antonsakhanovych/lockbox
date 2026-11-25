mod common;

use std::fs;
use std::sync::Arc;
use std::time::Duration;

use common::TestClock;
use lockbox_protocol::chunk::CHUNK_LEN;
use lockbox_protocol::crypto::envelope::Envelope;
use lockbox_protocol::crypto::keys::generate_keypair;
use lockbox_protocol::crypto::{SigningKey, VerifyingKey};
use lockbox_protocol::message::MAX_LIFETIME_SECS;
use lockbox_protocol::{Chunk, FetchHeader, FileHeader, FileId, SignedRequest};
use lockbox_server::adapters::driven::{DelayScheduler, DiskStore};
use lockbox_server::app::{Assembled, Services, assemble};
use lockbox_server::core::error::CoreError;
use lockbox_server::core::ports::driven::{FileStore, StoreError};
use lockbox_server::core::services::{ForDelete, ForFetch, ForUpload, Intent, Verified};
use tempfile::{TempDir, tempdir};
use tokio::task::JoinHandle;

const START: u64 = 1_000_000;

type Wired = Services<(TestClock, DiskStore, DelayScheduler)>;

struct World {
    dir: TempDir,
    clock: Arc<TestClock>,
    services: Arc<Wired>,
    store: Arc<DiskStore>,
    worker: JoinHandle<()>,
}

async fn world() -> World {
    let dir = tempdir().unwrap();
    let clock = TestClock::at(START);
    let store = Arc::new(DiskStore::new(dir.path().to_path_buf()).await.unwrap());
    let Assembled { services, worker } = assemble(clock.clone(), store.clone());
    World {
        worker: tokio::spawn(worker.run()),
        dir,
        clock,
        services,
        store,
    }
}

fn message(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn proof<I>(services: &Wired, id: FileId, key: &SigningKey) -> Verified<I>
where
    I: Intent,
{
    let challenge = services.challenges.issue(id, I::PURPOSE);
    let answer = SignedRequest::answer(&challenge, key);
    services.challenges.verify(challenge, &answer).unwrap()
}

struct Uploaded {
    id: FileId,
    expires_at: u64,
    ciphertext: Vec<u8>,
}

async fn upload(
    services: &Wired,
    owner: &SigningKey,
    recipients: &[VerifyingKey],
    plaintext: &[u8],
    lifetime: u64,
) -> Uploaded {
    let (envelope, ciphertext) = Envelope::encrypt_to_recipients(plaintext, recipients)
        .unwrap()
        .into_parts();
    let header = FileHeader {
        envelope,
        ciphertext_len: ciphertext.len() as u64,
        expires_at: START + lifetime,
    };
    let id = FileId::random();
    let who = proof::<ForUpload>(services, id, owner);
    let mut upload = services.uploads.begin(who, header).await.unwrap();
    for piece in ciphertext.chunks(CHUNK_LEN) {
        upload
            .write(&Chunk::new(piece.to_vec()).unwrap())
            .await
            .unwrap();
    }
    let expires_at = upload.finish().await.unwrap();
    Uploaded {
        id,
        expires_at,
        ciphertext,
    }
}

async fn download(
    services: &Wired,
    id: FileId,
    key: &SigningKey,
) -> Result<(FetchHeader, Vec<u8>), CoreError> {
    let who = proof::<ForFetch>(services, id, key);
    let mut fetch = services.fetches.begin(who).await?;
    let header = fetch.header().clone();
    let mut bytes = Vec::new();
    while let Some(chunk) = fetch.next_chunk().await? {
        bytes.extend_from_slice(chunk.as_bytes());
    }
    Ok((header, bytes))
}

async fn delete(services: &Wired, id: FileId, key: &SigningKey) -> Result<(), CoreError> {
    let who = proof::<ForDelete>(services, id, key);
    services.deletes.delete(who).await
}

fn stored_files(dir: &TempDir) -> usize {
    fs::read_dir(dir.path()).unwrap().count()
}

#[tokio::test]
async fn a_recipient_downloads_and_decrypts_what_the_owner_uploaded() {
    let w = world().await;
    let owner = generate_keypair();
    let recipient = generate_keypair();
    let sent = upload(
        &w.services,
        &owner,
        &[recipient.verifying_key()],
        b"the secret plans",
        60,
    )
    .await;
    let (header, bytes) = download(&w.services, sent.id, &recipient).await.unwrap();
    assert_eq!(bytes, sent.ciphertext);
    let plaintext = header.recipient.decrypt(&recipient, &bytes).unwrap();
    assert_eq!(plaintext, b"the secret plans");
}

#[tokio::test]
async fn a_file_larger_than_one_chunk_makes_the_round_trip() {
    let w = world().await;
    let owner = generate_keypair();
    let plaintext = message(CHUNK_LEN * 2 + 123);
    let sent = upload(
        &w.services,
        &owner,
        &[owner.verifying_key()],
        &plaintext,
        60,
    )
    .await;
    let (header, bytes) = download(&w.services, sent.id, &owner).await.unwrap();
    assert_eq!(header.recipient.decrypt(&owner, &bytes).unwrap(), plaintext);
}

#[tokio::test]
async fn every_recipient_can_download_and_decrypt() {
    let w = world().await;
    let owner = generate_keypair();
    let first = generate_keypair();
    let second = generate_keypair();
    let sent = upload(
        &w.services,
        &owner,
        &[first.verifying_key(), second.verifying_key()],
        b"shared",
        60,
    )
    .await;
    for key in [&first, &second] {
        let (header, bytes) = download(&w.services, sent.id, key).await.unwrap();
        assert_eq!(header.recipient.decrypt(key, &bytes).unwrap(), b"shared");
    }
}

#[tokio::test]
async fn someone_who_is_not_listed_cannot_download() {
    let w = world().await;
    let owner = generate_keypair();
    let recipient = generate_keypair();
    let sent = upload(&w.services, &owner, &[recipient.verifying_key()], b"x", 60).await;
    assert!(matches!(
        download(&w.services, sent.id, &generate_keypair()).await,
        Err(CoreError::Denied)
    ));
}

#[tokio::test]
async fn the_granted_expiry_is_returned_and_clamped() {
    let w = world().await;
    let owner = generate_keypair();
    let short = upload(&w.services, &owner, &[owner.verifying_key()], b"x", 120).await;
    let long = upload(&w.services, &owner, &[owner.verifying_key()], b"x", 10_000).await;
    assert_eq!(short.expires_at, START + 120);
    assert_eq!(long.expires_at, START + MAX_LIFETIME_SECS);
}

#[tokio::test]
async fn the_owner_can_delete_and_the_file_is_gone() {
    let w = world().await;
    let owner = generate_keypair();
    let sent = upload(&w.services, &owner, &[owner.verifying_key()], b"x", 60).await;
    delete(&w.services, sent.id, &owner).await.unwrap();
    assert!(matches!(
        download(&w.services, sent.id, &owner).await,
        Err(CoreError::Denied)
    ));
    assert!(matches!(
        w.store.open(sent.id).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        delete(&w.services, sent.id, &owner).await,
        Err(CoreError::Denied)
    ));
}

#[tokio::test]
async fn a_recipient_cannot_delete() {
    let w = world().await;
    let owner = generate_keypair();
    let recipient = generate_keypair();
    let sent = upload(&w.services, &owner, &[recipient.verifying_key()], b"x", 60).await;
    assert!(matches!(
        delete(&w.services, sent.id, &recipient).await,
        Err(CoreError::Denied)
    ));
    assert!(download(&w.services, sent.id, &recipient).await.is_ok());
}

#[tokio::test]
async fn a_proof_for_one_purpose_cannot_be_used_for_another() {
    let w = world().await;
    let owner = generate_keypair();
    let challenge = w
        .services
        .challenges
        .issue(FileId::random(), ForFetch::PURPOSE);
    let answer = SignedRequest::answer(&challenge, &owner);
    assert!(matches!(
        w.services
            .challenges
            .verify::<ForDelete>(challenge, &answer),
        Err(CoreError::Denied)
    ));
}

#[tokio::test]
async fn an_abandoned_upload_leaves_nothing_behind() {
    let w = world().await;
    let owner = generate_keypair();
    let (envelope, ciphertext) = Envelope::encrypt_to_recipients(b"x", &[owner.verifying_key()])
        .unwrap()
        .into_parts();
    let header = FileHeader {
        envelope,
        ciphertext_len: ciphertext.len() as u64,
        expires_at: START + 60,
    };
    let id = FileId::random();
    let who = proof::<ForUpload>(&w.services, id, &owner);
    let upload = w.services.uploads.begin(who, header).await.unwrap();
    drop(upload);
    assert!(matches!(
        download(&w.services, id, &owner).await,
        Err(CoreError::Denied)
    ));
    assert!(matches!(w.store.open(id).await, Err(StoreError::NotFound)));
}

#[tokio::test(start_paused = true)]
async fn a_file_expires_without_anyone_asking() {
    let w = world().await;
    let owner = generate_keypair();
    let sent = upload(&w.services, &owner, &[owner.verifying_key()], b"x", 60).await;
    tokio::task::yield_now().await;
    w.clock.advance(60);
    tokio::time::sleep(Duration::from_secs(61)).await;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while w.store.open(sent.id).await.is_ok() {
        assert!(std::time::Instant::now() < deadline, "never removed");
        tokio::task::yield_now().await;
    }
    assert!(matches!(
        download(&w.services, sent.id, &owner).await,
        Err(CoreError::Denied)
    ));
}

#[tokio::test(start_paused = true)]
async fn a_file_is_still_there_just_before_it_expires() {
    let w = world().await;
    let owner = generate_keypair();
    let sent = upload(&w.services, &owner, &[owner.verifying_key()], b"x", 60).await;
    tokio::task::yield_now().await;
    w.clock.advance(59);
    tokio::time::sleep(Duration::from_secs(59)).await;
    assert!(download(&w.services, sent.id, &owner).await.is_ok());
}

#[tokio::test]
async fn many_connections_can_use_the_same_services_at_once() {
    let w = world().await;
    let handles: Vec<_> = (0..8)
        .map(|n| {
            let services = w.services.clone();
            tokio::spawn(async move {
                let owner = generate_keypair();
                let recipient = generate_keypair();
                let plaintext = message(500 + n * 100);
                let sent = upload(
                    &services,
                    &owner,
                    &[recipient.verifying_key()],
                    &plaintext,
                    60,
                )
                .await;
                let (header, bytes) = download(&services, sent.id, &recipient).await.unwrap();
                assert_eq!(
                    header.recipient.decrypt(&recipient, &bytes).unwrap(),
                    plaintext
                );
                delete(&services, sent.id, &owner).await.unwrap();
            })
        })
        .collect();
    for handle in handles {
        handle.await.unwrap();
    }
    assert_eq!(stored_files(&w.dir), 0);
}

#[tokio::test]
async fn shutting_down_stops_the_worker_and_removes_every_file() {
    let World {
        dir,
        services,
        store,
        worker,
        ..
    } = world().await;
    let owner = generate_keypair();
    upload(&services, &owner, &[owner.verifying_key()], b"a", 60).await;
    upload(&services, &owner, &[owner.verifying_key()], b"b", 60).await;
    assert_eq!(stored_files(&dir), 2);
    drop(services);
    tokio::time::timeout(Duration::from_secs(10), worker)
        .await
        .unwrap()
        .unwrap();
    drop(store);
    assert_eq!(stored_files(&dir), 0);
}

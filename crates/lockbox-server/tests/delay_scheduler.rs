mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::TestClock;
use lockbox_protocol::crypto::SigningKey;
use lockbox_protocol::crypto::envelope::Envelope;
use lockbox_protocol::crypto::keys::generate_keypair;
use lockbox_protocol::{FileHeader, FileId, Purpose, SignedRequest};
use lockbox_server::adapters::driven::{DelayScheduler, DiskStore};
use lockbox_server::core::ports::driven::{ExpiryScheduler, FileStore, StoreError};
use lockbox_server::core::services::{Challenges, Expiry, Registry};
use tempfile::{TempDir, tempdir};
use tokio::io::AsyncWriteExt;
use tokio::task::JoinHandle;

const START: u64 = 1_000_000;

struct World {
    _dir: TempDir,
    clock: Arc<TestClock>,
    challenges: Challenges<TestClock>,
    registry: Arc<Registry<TestClock>>,
    store: Arc<DiskStore>,
    scheduler: DelayScheduler,
    worker: JoinHandle<()>,
}

async fn world() -> World {
    let dir = tempdir().unwrap();
    let clock = TestClock::at(START);
    let store = Arc::new(DiskStore::new(dir.path().to_path_buf()).await.unwrap());
    let registry = Arc::new(Registry::new(clock.clone()));
    let expiry = Arc::new(Expiry::new(registry.clone(), store.clone()));
    let (scheduler, worker) = DelayScheduler::new(clock.clone(), expiry);
    World {
        worker: tokio::spawn(worker.run()),
        scheduler,
        challenges: Challenges::new(clock.clone()),
        registry,
        store,
        clock,
        _dir: dir,
    }
}

impl World {
    async fn put(&self, owner: &SigningKey, lifetime: u64) -> FileId {
        let (envelope, ciphertext) =
            Envelope::encrypt_to_recipients(b"hello", &[owner.verifying_key()])
                .unwrap()
                .into_parts();
        let header = FileHeader {
            envelope,
            ciphertext_len: ciphertext.len() as u64,
            expires_at: START + lifetime,
        };
        let id = FileId::random();
        let mut writer = self.store.create(id).await.unwrap();
        writer.write_all(&ciphertext).await.unwrap();
        writer.shutdown().await.unwrap();
        let challenge = self.challenges.issue(id, Purpose::Upload);
        let proof = SignedRequest::answer(&challenge, owner);
        let who = self
            .challenges
            .verify(challenge, &proof, Purpose::Upload)
            .unwrap();
        self.registry.register(&who, header).unwrap();
        id
    }

    async fn schedule(&self, id: FileId, expires_at: u64) {
        self.scheduler.schedule(id, expires_at);
        tokio::task::yield_now().await;
    }

    async fn wait_until_gone(&self, id: FileId) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.store.open(id).await.is_ok() {
            assert!(Instant::now() < deadline, "the file was never removed");
            tokio::task::yield_now().await;
        }
    }

    async fn is_stored(&self, id: FileId) -> bool {
        self.store.open(id).await.is_ok()
    }
}

#[tokio::test(start_paused = true)]
async fn a_file_is_removed_when_its_time_comes() {
    let w = world().await;
    let owner = generate_keypair();
    let id = w.put(&owner, 60).await;
    w.schedule(id, START + 60).await;
    w.clock.advance(60);
    tokio::time::sleep(Duration::from_secs(61)).await;
    w.wait_until_gone(id).await;
    assert!(matches!(w.store.open(id).await, Err(StoreError::NotFound)));
}

#[tokio::test(start_paused = true)]
async fn a_file_is_kept_until_then() {
    let w = world().await;
    let owner = generate_keypair();
    let id = w.put(&owner, 60).await;
    w.schedule(id, START + 60).await;
    tokio::time::sleep(Duration::from_secs(59)).await;
    assert!(w.is_stored(id).await);
}

#[tokio::test(start_paused = true)]
async fn a_time_in_the_past_fires_at_once() {
    let w = world().await;
    let owner = generate_keypair();
    let id = w.put(&owner, 60).await;
    w.clock.advance(100);
    w.schedule(id, START + 60).await;
    w.wait_until_gone(id).await;
}

#[tokio::test(start_paused = true)]
async fn files_expire_in_the_order_of_their_times_not_of_scheduling() {
    let w = world().await;
    let owner = generate_keypair();
    let late = w.put(&owner, 120).await;
    let early = w.put(&owner, 60).await;
    w.schedule(late, START + 120).await;
    w.schedule(early, START + 60).await;
    w.clock.advance(60);
    tokio::time::sleep(Duration::from_secs(61)).await;
    w.wait_until_gone(early).await;
    assert!(w.is_stored(late).await);
    w.clock.advance(60);
    tokio::time::sleep(Duration::from_secs(60)).await;
    w.wait_until_gone(late).await;
}

#[tokio::test(start_paused = true)]
async fn a_file_deleted_before_its_time_does_not_stop_the_worker() {
    let w = world().await;
    let owner = generate_keypair();
    let gone = w.put(&owner, 60).await;
    w.schedule(gone, START + 60).await;
    let challenge = w.challenges.issue(gone, Purpose::Delete);
    let proof = SignedRequest::answer(&challenge, &owner);
    let who = w
        .challenges
        .verify(challenge, &proof, Purpose::Delete)
        .unwrap();
    w.registry.delete(&who).unwrap();
    w.store.remove(gone).await.unwrap();
    let other = w.put(&owner, 90).await;
    w.schedule(other, START + 90).await;
    w.clock.advance(90);
    tokio::time::sleep(Duration::from_secs(91)).await;
    w.wait_until_gone(other).await;
}

#[tokio::test(start_paused = true)]
async fn a_file_scheduled_while_the_worker_waits_is_picked_up() {
    let w = world().await;
    let owner = generate_keypair();
    let first = w.put(&owner, 200).await;
    w.schedule(first, START + 200).await;
    tokio::time::sleep(Duration::from_secs(10)).await;
    w.clock.advance(10);
    let second = w.put(&owner, 40).await;
    w.schedule(second, START + 40).await;
    w.clock.advance(30);
    tokio::time::sleep(Duration::from_secs(31)).await;
    w.wait_until_gone(second).await;
    assert!(w.is_stored(first).await);
}

#[tokio::test(start_paused = true)]
async fn the_worker_stops_when_the_scheduler_is_dropped() {
    let w = world().await;
    let World {
        scheduler, worker, ..
    } = w;
    drop(scheduler);
    tokio::time::timeout(Duration::from_secs(10), worker)
        .await
        .unwrap()
        .unwrap();
}

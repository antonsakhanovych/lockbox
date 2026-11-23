use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use lockbox_protocol::FileId;
use lockbox_server::core::ports::driven::{Clock, ExpiryScheduler};

pub struct TestClock(AtomicU64);

impl TestClock {
    pub fn at(now: u64) -> Arc<Self> {
        Arc::new(Self(AtomicU64::new(now)))
    }

    pub fn advance(&self, secs: u64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[allow(dead_code)]
#[derive(Default)]
pub struct RecordingScheduler(Mutex<Vec<(FileId, u64)>>);

#[allow(dead_code)]
impl RecordingScheduler {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn calls(&self) -> Vec<(FileId, u64)> {
        self.0.lock().unwrap().clone()
    }
}

impl ExpiryScheduler for RecordingScheduler {
    fn schedule(&self, file_id: FileId, expires_at: u64) {
        self.0.lock().unwrap().push((file_id, expires_at));
    }
}

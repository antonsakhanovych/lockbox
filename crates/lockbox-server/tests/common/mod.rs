use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use lockbox_server::core::ports::driven::Clock;

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

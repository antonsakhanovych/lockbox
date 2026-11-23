use std::future::poll_fn;
use std::sync::Arc;
use std::time::Duration;

use lockbox_protocol::FileId;
use tokio::sync::mpsc;
use tokio_util::time::DelayQueue;

use crate::core::ports::driven::{Clock, ExpiryScheduler, FileStore};
use crate::core::services::Expiry;

pub struct DelayScheduler {
    sender: mpsc::UnboundedSender<(FileId, u64)>,
}

pub struct ExpiryWorker<C, S> {
    receiver: mpsc::UnboundedReceiver<(FileId, u64)>,
    clock: Arc<C>,
    expiry: Arc<Expiry<C, S>>,
}

impl DelayScheduler {
    pub fn new<C, S>(clock: Arc<C>, expiry: Arc<Expiry<C, S>>) -> (Self, ExpiryWorker<C, S>)
    where
        C: Clock,
        S: FileStore,
    {
        let (sender, receiver) = mpsc::unbounded_channel();
        let worker = ExpiryWorker {
            receiver,
            clock,
            expiry,
        };
        (Self { sender }, worker)
    }
}

impl ExpiryScheduler for DelayScheduler {
    fn schedule(&self, file_id: FileId, expires_at: u64) {
        let _ = self.sender.send((file_id, expires_at));
    }
}

impl<C, S> ExpiryWorker<C, S>
where
    C: Clock,
    S: FileStore,
{
    pub async fn run(mut self) {
        let mut queue = DelayQueue::new();
        loop {
            tokio::select! {
                scheduled = self.receiver.recv() => match scheduled {
                    Some((file_id, expires_at)) => {
                        let wait = expires_at.saturating_sub(self.clock.now());
                        queue.insert(file_id, Duration::from_secs(wait));
                    }
                    None => break,
                },
                Some(expired) = poll_fn(|cx| queue.poll_expired(cx)) => {
                    let file_id = expired.into_inner();
                    if let Err(error) = self.expiry.expire(file_id).await {
                        tracing::error!(%file_id, %error, "could not remove an expired file");
                    }
                }
            }
        }
    }
}

use lockbox_protocol::FileId;

pub trait ExpiryScheduler: Send + Sync {
    fn schedule(&self, file_id: FileId, expires_at: u64);
}

use std::sync::Arc;

use lockbox_protocol::FileId;

use crate::core::error::Result;
use crate::core::ports::driven::{Clock, FileStore, StoreError};
use crate::core::services::Registry;

pub struct Expiry<C, S> {
    registry: Arc<Registry<C>>,
    store: Arc<S>,
}

impl<C, S> Expiry<C, S>
where
    C: Clock,
    S: FileStore,
{
    pub fn new(registry: Arc<Registry<C>>, store: Arc<S>) -> Self {
        Self { registry, store }
    }

    pub async fn expire(&self, file_id: FileId) -> Result<()> {
        if !self.registry.expire(file_id) {
            return Ok(());
        }
        match self.store.remove(file_id).await {
            Ok(()) | Err(StoreError::NotFound) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

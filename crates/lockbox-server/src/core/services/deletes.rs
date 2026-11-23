use std::sync::Arc;

use crate::core::error::Result;
use crate::core::ports::driven::{Clock, FileStore, StoreError};
use crate::core::services::{Registry, Verified};

pub struct Deletes<C, S> {
    registry: Arc<Registry<C>>,
    store: Arc<S>,
}

impl<C, S> Deletes<C, S>
where
    C: Clock,
    S: FileStore,
{
    pub fn new(registry: Arc<Registry<C>>, store: Arc<S>) -> Self {
        Self { registry, store }
    }

    pub async fn delete(&self, requester: Verified) -> Result<()> {
        self.registry.delete(&requester)?;
        match self.store.remove(requester.file_id()).await {
            Ok(()) | Err(StoreError::NotFound) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

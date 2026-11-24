use std::sync::Arc;

use lockbox_protocol::transfer::write_chunk;
use lockbox_protocol::{Chunk, FileHeader, FileId, ProtocolError};
use tokio::io::AsyncWriteExt;

use crate::core::error::{CoreError, Result};
use crate::core::ports::driven::{Clock, ExpiryScheduler, FileStore, StoreError};
use crate::core::services::{ForUpload, Registry, Verified};

pub struct Uploads<C, S, X> {
    registry: Arc<Registry<C>>,
    store: Arc<S>,
    scheduler: Arc<X>,
}

impl<C, S, X> Uploads<C, S, X>
where
    C: Clock,
    S: FileStore,
    X: ExpiryScheduler,
{
    pub fn new(registry: Arc<Registry<C>>, store: Arc<S>, scheduler: Arc<X>) -> Self {
        Self {
            registry,
            store,
            scheduler,
        }
    }

    pub async fn begin(
        &self,
        owner: Verified<ForUpload>,
        header: FileHeader,
    ) -> Result<Upload<C, S, X>> {
        header.validate().map_err(|_| CoreError::Invalid)?;
        let writer = self.store.create(owner.file_id()).await?;
        Ok(Upload {
            remaining: header.ciphertext_len,
            owner,
            header,
            writer,
            registry: self.registry.clone(),
            store: self.store.clone(),
            scheduler: self.scheduler.clone(),
        })
    }
}

pub struct Upload<C, S, X>
where
    S: FileStore,
{
    owner: Verified<ForUpload>,
    header: FileHeader,
    remaining: u64,
    writer: S::Writer,
    registry: Arc<Registry<C>>,
    store: Arc<S>,
    scheduler: Arc<X>,
}

impl<C, S, X> Upload<C, S, X>
where
    C: Clock,
    S: FileStore,
    X: ExpiryScheduler,
{
    pub fn file_id(&self) -> FileId {
        self.owner.file_id()
    }

    pub fn remaining(&self) -> u64 {
        self.remaining
    }

    pub async fn write(&mut self, chunk: &Chunk) -> Result<()> {
        self.remaining = write_chunk(chunk, &mut self.writer, self.remaining)
            .await
            .map_err(|error| match error {
                ProtocolError::Io(source) => CoreError::Store(StoreError::Io(source)),
                _ => CoreError::Invalid,
            })?;
        Ok(())
    }

    pub async fn finish(mut self) -> Result<u64> {
        if self.remaining > 0 {
            return Err(CoreError::Invalid);
        }
        self.writer.shutdown().await.map_err(StoreError::Io)?;
        match self.registry.register(&self.owner, self.header) {
            Ok(expires_at) => {
                self.scheduler.schedule(self.owner.file_id(), expires_at);
                Ok(expires_at)
            }
            Err(error) => {
                let _ = self.store.remove(self.owner.file_id()).await;
                Err(error)
            }
        }
    }
}

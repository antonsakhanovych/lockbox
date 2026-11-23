use std::sync::Arc;

use lockbox_protocol::transfer::write_chunk;
use lockbox_protocol::{Chunk, FileHeader, FileId, ProtocolError};
use tokio::io::AsyncWriteExt;

use crate::core::error::{CoreError, Result};
use crate::core::ports::driven::{Clock, FileStore, StoreError};
use crate::core::services::{Registry, Verified};

pub struct Uploads<C, S> {
    registry: Arc<Registry<C>>,
    store: Arc<S>,
}

impl<C, S> Uploads<C, S>
where
    C: Clock,
    S: FileStore,
{
    pub fn new(registry: Arc<Registry<C>>, store: Arc<S>) -> Self {
        Self { registry, store }
    }

    pub async fn begin(&self, owner: Verified, header: FileHeader) -> Result<Upload<C, S>> {
        header.validate().map_err(|_| CoreError::Invalid)?;
        let writer = self.store.create(owner.file_id()).await?;
        Ok(Upload {
            remaining: header.ciphertext_len,
            owner,
            header,
            writer,
            registry: self.registry.clone(),
            store: self.store.clone(),
        })
    }
}

pub struct Upload<C, S>
where
    S: FileStore,
{
    owner: Verified,
    header: FileHeader,
    remaining: u64,
    writer: S::Writer,
    registry: Arc<Registry<C>>,
    store: Arc<S>,
}

impl<C, S> Upload<C, S>
where
    C: Clock,
    S: FileStore,
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
            Ok(expires_at) => Ok(expires_at),
            Err(error) => {
                let _ = self.store.remove(self.owner.file_id()).await;
                Err(error)
            }
        }
    }
}

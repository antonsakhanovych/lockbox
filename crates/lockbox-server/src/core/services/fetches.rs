use std::sync::Arc;

use lockbox_protocol::chunk::CHUNK_LEN;
use lockbox_protocol::{Chunk, FetchHeader};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::core::error::{CoreError, Result};
use crate::core::ports::driven::{Clock, FileStore, StoreError};
use crate::core::services::{Registry, Verified};

pub struct Fetches<C, S> {
    registry: Arc<Registry<C>>,
    store: Arc<S>,
}

impl<C, S> Fetches<C, S>
where
    C: Clock,
    S: FileStore,
{
    pub fn new(registry: Arc<Registry<C>>, store: Arc<S>) -> Self {
        Self { registry, store }
    }

    pub async fn begin(&self, requester: Verified) -> Result<Fetch<S::Reader>> {
        let header = self.registry.fetch_header(&requester)?;
        let reader = match self.store.open(requester.file_id()).await {
            Ok(reader) => reader,
            Err(StoreError::NotFound) => return Err(CoreError::Denied),
            Err(error) => return Err(error.into()),
        };
        Ok(Fetch {
            remaining: header.ciphertext_len,
            header,
            reader,
        })
    }
}

pub struct Fetch<R> {
    header: FetchHeader,
    remaining: u64,
    reader: R,
}

impl<R> Fetch<R>
where
    R: AsyncRead + Unpin,
{
    pub fn header(&self) -> &FetchHeader {
        &self.header
    }

    pub fn remaining(&self) -> u64 {
        self.remaining
    }

    pub async fn next_chunk(&mut self) -> Result<Option<Chunk>> {
        if self.remaining == 0 {
            return Ok(None);
        }
        let len = self.remaining.min(CHUNK_LEN as u64) as usize;
        let mut bytes = vec![0; len];
        self.reader
            .read_exact(&mut bytes)
            .await
            .map_err(StoreError::Io)?;
        self.remaining -= len as u64;
        Chunk::new(bytes).map(Some).map_err(|_| CoreError::Invalid)
    }
}

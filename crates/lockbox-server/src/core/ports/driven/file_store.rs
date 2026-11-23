use std::future::Future;

use lockbox_protocol::FileId;
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("the file is not in the store")]
    NotFound,
}

pub trait FileStore: Send + Sync {
    type Writer: AsyncWrite + Unpin + Send;
    type Reader: AsyncRead + Unpin + Send;

    fn create(
        &self,
        file_id: FileId,
    ) -> impl Future<Output = Result<Self::Writer, StoreError>> + Send;

    fn open(
        &self,
        file_id: FileId,
    ) -> impl Future<Output = Result<Self::Reader, StoreError>> + Send;

    fn remove(&self, file_id: FileId) -> impl Future<Output = Result<(), StoreError>> + Send;
}

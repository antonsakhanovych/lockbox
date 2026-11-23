use crate::core::ports::driven::StoreError;

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("the request was denied")]
    Denied,

    #[error("the request was invalid")]
    Invalid,

    #[error("the file store failed: {0}")]
    Store(#[from] StoreError),
}

pub type Result<T> = std::result::Result<T, CoreError>;

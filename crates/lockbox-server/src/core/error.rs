use lockbox_protocol::ErrorCode;

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

impl From<&CoreError> for ErrorCode {
    fn from(error: &CoreError) -> Self {
        match error {
            CoreError::Denied => Self::Denied,
            CoreError::Invalid => Self::InvalidRequest,
            CoreError::Store(_) => Self::Internal,
        }
    }
}

pub type Result<T> = std::result::Result<T, CoreError>;

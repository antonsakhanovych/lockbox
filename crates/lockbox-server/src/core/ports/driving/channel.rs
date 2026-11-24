use std::future::Future;

use lockbox_protocol::{ErrorCode, ProtocolError, Request, Response};

#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("malformed message: {0}")]
    Codec(ProtocolError),
}

pub trait Channel: Send {
    fn receive(&mut self) -> impl Future<Output = Result<Option<Request>, ChannelError>> + Send;

    fn send(
        &mut self,
        response: &Response,
    ) -> impl Future<Output = Result<(), ChannelError>> + Send;
}

impl From<ProtocolError> for ChannelError {
    fn from(error: ProtocolError) -> Self {
        match error {
            ProtocolError::Io(error) => Self::Io(error),
            other => Self::Codec(other),
        }
    }
}

impl From<&ChannelError> for ErrorCode {
    fn from(error: &ChannelError) -> Self {
        match error {
            ChannelError::Io(_) => Self::Internal,
            ChannelError::Codec(
                ProtocolError::Encode(_) | ProtocolError::MessageTooLarge { .. },
            ) => Self::Internal,
            ChannelError::Codec(_) => Self::InvalidRequest,
        }
    }
}

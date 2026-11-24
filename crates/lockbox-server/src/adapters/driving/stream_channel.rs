use lockbox_protocol::codec::{read_message, write_message};
use lockbox_protocol::{ProtocolError, Request, Response};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::core::ports::driving::{Channel, ChannelError};

pub struct StreamChannel<S> {
    stream: S,
}

impl<S> StreamChannel<S> {
    pub fn new(stream: S) -> Self {
        Self { stream }
    }
}

impl<S> Channel for StreamChannel<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    async fn receive(&mut self) -> Result<Option<Request>, ChannelError> {
        match read_message(&mut self.stream).await {
            Ok(request) => Ok(Some(request)),
            Err(ProtocolError::ConnectionClosed) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    async fn send(&mut self, response: &Response) -> Result<(), ChannelError> {
        write_message(&mut self.stream, response)
            .await
            .map_err(ChannelError::from)
    }
}

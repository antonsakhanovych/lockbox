use futures_util::{SinkExt, StreamExt};
use lockbox_protocol::codec::{MAX_MESSAGE_LEN, decode, encode};
use lockbox_protocol::{ProtocolError, Request, Response};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_tungstenite::{WebSocketStream, accept_async_with_config};

use crate::core::ports::driving::{Channel, ChannelError};

pub struct WebSocketChannel<S> {
    socket: WebSocketStream<S>,
}

impl<S> WebSocketChannel<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn accept(stream: S) -> Result<Self, ChannelError> {
        let config = WebSocketConfig::default()
            .max_message_size(Some(MAX_MESSAGE_LEN))
            .max_frame_size(Some(MAX_MESSAGE_LEN));
        let socket = accept_async_with_config(stream, Some(config))
            .await
            .map_err(ChannelError::from)?;
        Ok(Self { socket })
    }

    pub fn new(socket: WebSocketStream<S>) -> Self {
        Self { socket }
    }
}

impl<S> Channel for WebSocketChannel<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    async fn receive(&mut self) -> Result<Option<Request>, ChannelError> {
        loop {
            let message = match self.socket.next().await {
                None | Some(Err(WsError::ConnectionClosed | WsError::AlreadyClosed)) => {
                    return Ok(None);
                }
                Some(Err(error)) => return Err(error.into()),
                Some(Ok(message)) => message,
            };
            match message {
                Message::Binary(bytes) => return Ok(Some(decode(&bytes)?)),
                Message::Close(_) => return Ok(None),
                Message::Text(_) => {
                    return Err(ChannelError::Codec(ProtocolError::UnexpectedMessage));
                }
                Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
            }
        }
    }

    async fn send(&mut self, response: &Response) -> Result<(), ChannelError> {
        let bytes = encode(response)?;
        self.socket.send(Message::Binary(bytes.into())).await?;
        Ok(())
    }
}

impl From<WsError> for ChannelError {
    fn from(error: WsError) -> Self {
        match error {
            WsError::Io(error) => Self::Io(error),
            WsError::Capacity(_) => Self::Codec(ProtocolError::MessageLimitExceeded {
                max: MAX_MESSAGE_LEN,
            }),
            other => Self::Io(std::io::Error::other(other)),
        }
    }
}

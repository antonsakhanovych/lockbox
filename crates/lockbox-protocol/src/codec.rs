use std::io::ErrorKind;

use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{ProtocolError, Result};

pub const MAX_MESSAGE_LEN: usize = 1024 * 1024;

pub const LENGTH_PREFIX_LEN: usize = 4;

pub fn encode<T>(message: &T) -> Result<Vec<u8>>
where
    T: Serialize,
{
    let bytes = postcard::to_stdvec(message).map_err(ProtocolError::Encode)?;
    if bytes.len() > MAX_MESSAGE_LEN {
        return Err(ProtocolError::MessageTooLarge {
            len: bytes.len(),
            max: MAX_MESSAGE_LEN,
        });
    }
    Ok(bytes)
}

pub fn decode<T>(bytes: &[u8]) -> Result<T>
where
    T: DeserializeOwned,
{
    if bytes.len() > MAX_MESSAGE_LEN {
        return Err(ProtocolError::MessageLimitExceeded {
            max: MAX_MESSAGE_LEN,
        });
    }
    let (message, rest) = postcard::take_from_bytes(bytes).map_err(ProtocolError::Decode)?;
    if !rest.is_empty() {
        return Err(ProtocolError::TrailingBytes);
    }
    Ok(message)
}

pub async fn write_message<T, W>(writer: &mut W, message: &T) -> Result<()>
where
    T: Serialize,
    W: AsyncWrite + Unpin,
{
    let bytes = encode(message)?;
    writer
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .await?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_message<T, R>(reader: &mut R) -> Result<T>
where
    T: DeserializeOwned,
    R: AsyncRead + Unpin,
{
    let mut prefix = [0u8; LENGTH_PREFIX_LEN];
    read_exact(reader, &mut prefix).await?;
    let len = u32::from_be_bytes(prefix) as usize;
    if len > MAX_MESSAGE_LEN {
        return Err(ProtocolError::MessageLimitExceeded {
            max: MAX_MESSAGE_LEN,
        });
    }
    let mut bytes = vec![0u8; len];
    read_exact(reader, &mut bytes).await?;
    decode(&bytes)
}

async fn read_exact<R>(reader: &mut R, buf: &mut [u8]) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    match reader.read_exact(buf).await {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == ErrorKind::UnexpectedEof => {
            Err(ProtocolError::ConnectionClosed)
        }
        Err(error) => Err(error.into()),
    }
}

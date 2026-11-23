use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::chunk::{CHUNK_LEN, Chunk};
use crate::codec::{read_message, write_message};
use crate::error::{ProtocolError, Result};
use crate::message::{Request, Response};

pub async fn send_upload<W>(writer: &mut W, ciphertext: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    for piece in ciphertext.chunks(CHUNK_LEN) {
        let chunk = Chunk::new(piece.to_vec())?;
        write_message(writer, &Request::UploadChunk(chunk)).await?;
    }
    Ok(())
}

pub async fn send_fetch<W>(writer: &mut W, ciphertext: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    for piece in ciphertext.chunks(CHUNK_LEN) {
        let chunk = Chunk::new(piece.to_vec())?;
        write_message(writer, &Response::Chunk(chunk)).await?;
    }
    Ok(())
}

pub async fn receive_upload<R, W>(reader: &mut R, sink: &mut W, expected_len: u64) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut remaining = expected_len;
    while remaining > 0 {
        match read_message(reader).await? {
            Request::UploadChunk(chunk) => remaining = write_chunk(&chunk, sink, remaining).await?,
            _ => return Err(ProtocolError::UnexpectedMessage),
        }
    }
    Ok(())
}

pub async fn receive_fetch<R, W>(reader: &mut R, sink: &mut W, expected_len: u64) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut remaining = expected_len;
    while remaining > 0 {
        match read_message(reader).await? {
            Response::Chunk(chunk) => remaining = write_chunk(&chunk, sink, remaining).await?,
            Response::Error(code) => return Err(ProtocolError::Remote(code)),
            _ => return Err(ProtocolError::UnexpectedMessage),
        }
    }
    Ok(())
}

pub async fn write_chunk<W>(chunk: &Chunk, sink: &mut W, remaining: u64) -> Result<u64>
where
    W: AsyncWrite + Unpin,
{
    let bytes = chunk.as_bytes();
    if bytes.is_empty() {
        return Err(ProtocolError::EmptyChunk);
    }
    if bytes.len() as u64 > remaining {
        return Err(ProtocolError::TransferOverflow);
    }
    sink.write_all(bytes).await?;
    Ok(remaining - bytes.len() as u64)
}

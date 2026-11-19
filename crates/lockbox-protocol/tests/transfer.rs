use std::io::{self, Cursor};
use std::pin::Pin;
use std::task::{Context, Poll};

mod common;

use lockbox_protocol::chunk::CHUNK_LEN;
use lockbox_protocol::codec::{read_message, write_message};
use lockbox_protocol::transfer::{receive_fetch, receive_upload, send_fetch, send_upload};
use lockbox_protocol::{Chunk, ErrorCode, ProtocolError, Request, Response};
use tokio::io::AsyncWrite;

fn data(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

async fn upload_wire(ciphertext: &[u8]) -> Vec<u8> {
    let mut wire = Vec::new();
    send_upload(&mut wire, ciphertext).await.unwrap();
    wire
}

async fn fetch_wire(ciphertext: &[u8]) -> Vec<u8> {
    let mut wire = Vec::new();
    send_fetch(&mut wire, ciphertext).await.unwrap();
    wire
}

async fn uploaded(wire: &[u8], expected_len: u64) -> Result<Vec<u8>, ProtocolError> {
    let mut sink = Vec::new();
    receive_upload(&mut Cursor::new(wire), &mut sink, expected_len).await?;
    Ok(sink)
}

async fn fetched(wire: &[u8], expected_len: u64) -> Result<Vec<u8>, ProtocolError> {
    let mut sink = Vec::new();
    receive_fetch(&mut Cursor::new(wire), &mut sink, expected_len).await?;
    Ok(sink)
}

async fn upload_chunk_sizes(wire: &[u8]) -> Vec<usize> {
    let mut reader = Cursor::new(wire);
    let mut sizes = Vec::new();
    while let Ok(Request::UploadChunk(chunk)) = read_message(&mut reader).await {
        sizes.push(chunk.as_bytes().len());
    }
    sizes
}

async fn fetch_chunk_sizes(wire: &[u8]) -> Vec<usize> {
    let mut reader = Cursor::new(wire);
    let mut sizes = Vec::new();
    while let Ok(Response::Chunk(chunk)) = read_message(&mut reader).await {
        sizes.push(chunk.as_bytes().len());
    }
    sizes
}

struct CountingSink {
    writes: Vec<usize>,
    bytes: Vec<u8>,
}

impl AsyncWrite for CountingSink {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.writes.push(buf.len());
        self.bytes.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct Broken(io::ErrorKind);

impl AsyncWrite for Broken {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(self.0.into()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

const SIZES: [usize; 8] = [
    1,
    16,
    1000,
    CHUNK_LEN - 1,
    CHUNK_LEN,
    CHUNK_LEN + 1,
    3 * CHUNK_LEN,
    3 * CHUNK_LEN + 5,
];

#[tokio::test]
async fn an_upload_of_every_interesting_size_round_trips() {
    for len in SIZES {
        let ciphertext = data(len);
        assert_eq!(
            uploaded(&upload_wire(&ciphertext).await, len as u64)
                .await
                .unwrap(),
            ciphertext,
            "{len}"
        );
    }
}

#[tokio::test]
async fn a_fetch_of_every_interesting_size_round_trips() {
    for len in SIZES {
        let ciphertext = data(len);
        assert_eq!(
            fetched(&fetch_wire(&ciphertext).await, len as u64)
                .await
                .unwrap(),
            ciphertext,
            "{len}"
        );
    }
}

#[tokio::test]
async fn each_chunk_is_a_message_with_its_kind_byte() {
    let upload = upload_wire(&data(10)).await;
    let fetch = fetch_wire(&data(10)).await;
    assert_eq!(common::body(upload.clone())[0], 4);
    assert_eq!(common::body(fetch.clone())[0], 4);
    assert_eq!(
        read_message::<Request, _>(&mut Cursor::new(&upload))
            .await
            .unwrap(),
        Request::UploadChunk(Chunk::new(data(10)).unwrap())
    );
    assert_eq!(
        read_message::<Response, _>(&mut Cursor::new(&fetch))
            .await
            .unwrap(),
        Response::Chunk(Chunk::new(data(10)).unwrap())
    );
}

#[tokio::test]
async fn the_ciphertext_is_cut_into_full_chunks_and_one_remainder() {
    assert_eq!(
        upload_chunk_sizes(&upload_wire(&data(2 * CHUNK_LEN + 100)).await).await,
        [CHUNK_LEN, CHUNK_LEN, 100]
    );
    assert_eq!(
        fetch_chunk_sizes(&fetch_wire(&data(2 * CHUNK_LEN + 100)).await).await,
        [CHUNK_LEN, CHUNK_LEN, 100]
    );
}

#[tokio::test]
async fn an_exact_multiple_of_the_chunk_size_has_no_extra_chunk() {
    assert_eq!(
        upload_chunk_sizes(&upload_wire(&data(2 * CHUNK_LEN)).await).await,
        [CHUNK_LEN, CHUNK_LEN]
    );
}

#[tokio::test]
async fn sending_nothing_writes_nothing() {
    assert!(upload_wire(&[]).await.is_empty());
    assert!(fetch_wire(&[]).await.is_empty());
}

#[tokio::test]
async fn the_sink_receives_the_data_one_chunk_at_a_time() {
    let ciphertext = data(CHUNK_LEN + 10);
    let mut sink = CountingSink {
        writes: Vec::new(),
        bytes: Vec::new(),
    };
    receive_fetch(
        &mut Cursor::new(fetch_wire(&ciphertext).await),
        &mut sink,
        ciphertext.len() as u64,
    )
    .await
    .unwrap();
    assert_eq!(sink.writes, [CHUNK_LEN, 10]);
    assert_eq!(sink.bytes, ciphertext);
}

#[tokio::test]
async fn receiving_an_upload_stops_exactly_at_the_announced_length() {
    let mut wire = upload_wire(&data(CHUNK_LEN + 3)).await;
    write_message(&mut wire, &Request::BeginUpload)
        .await
        .unwrap();
    let mut reader = Cursor::new(wire);
    let mut sink = Vec::new();
    receive_upload(&mut reader, &mut sink, (CHUNK_LEN + 3) as u64)
        .await
        .unwrap();
    assert_eq!(
        read_message::<Request, _>(&mut reader).await.unwrap(),
        Request::BeginUpload
    );
}

#[tokio::test]
async fn receiving_zero_bytes_reads_nothing() {
    let mut sink = Vec::new();
    receive_upload(&mut Cursor::new(Vec::new()), &mut sink, 0)
        .await
        .unwrap();
    receive_fetch(&mut Cursor::new(Vec::new()), &mut sink, 0)
        .await
        .unwrap();
    assert!(sink.is_empty());
}

#[tokio::test]
async fn more_data_than_announced_is_rejected() {
    assert!(matches!(
        uploaded(&upload_wire(&data(1000)).await, 999).await,
        Err(ProtocolError::TransferOverflow)
    ));
    assert!(matches!(
        fetched(
            &fetch_wire(&data(2 * CHUNK_LEN)).await,
            (CHUNK_LEN + 1) as u64
        )
        .await,
        Err(ProtocolError::TransferOverflow)
    ));
}

#[tokio::test]
async fn less_data_than_announced_means_the_connection_closed() {
    assert!(matches!(
        uploaded(&upload_wire(&data(CHUNK_LEN)).await, (CHUNK_LEN + 1) as u64).await,
        Err(ProtocolError::ConnectionClosed)
    ));
    assert!(matches!(
        fetched(&[], 5).await,
        Err(ProtocolError::ConnectionClosed)
    ));
}

#[tokio::test]
async fn a_stream_cut_inside_a_chunk_means_the_connection_closed() {
    let wire = upload_wire(&data(1000)).await;
    for length in [1, 2, 10, wire.len() - 1] {
        assert!(matches!(
            uploaded(&wire[..length], 1000).await,
            Err(ProtocolError::ConnectionClosed)
        ));
    }
}

#[tokio::test]
async fn another_kind_of_request_in_an_upload_is_rejected() {
    let mut wire = Vec::new();
    write_message(&mut wire, &Request::BeginUpload)
        .await
        .unwrap();
    assert!(matches!(
        uploaded(&wire, 10).await,
        Err(ProtocolError::UnexpectedMessage)
    ));

    let mut wire = upload_wire(&data(CHUNK_LEN)).await;
    write_message(&mut wire, &Request::BeginUpload)
        .await
        .unwrap();
    assert!(matches!(
        uploaded(&wire, (CHUNK_LEN + 10) as u64).await,
        Err(ProtocolError::UnexpectedMessage)
    ));
}

#[tokio::test]
async fn another_kind_of_response_in_a_fetch_is_rejected() {
    let mut wire = Vec::new();
    write_message(&mut wire, &Response::Deleted).await.unwrap();
    assert!(matches!(
        fetched(&wire, 10).await,
        Err(ProtocolError::UnexpectedMessage)
    ));
}

#[tokio::test]
async fn an_error_from_the_server_in_the_middle_of_a_fetch_is_reported() {
    let mut wire = fetch_wire(&data(CHUNK_LEN)).await;
    write_message(&mut wire, &Response::Error(ErrorCode::Internal))
        .await
        .unwrap();
    assert!(matches!(
        fetched(&wire, (2 * CHUNK_LEN) as u64).await,
        Err(ProtocolError::Remote(ErrorCode::Internal))
    ));
}

#[tokio::test]
async fn an_empty_chunk_is_rejected() {
    let mut wire = Vec::new();
    write_message(
        &mut wire,
        &Request::UploadChunk(Chunk::new(vec![]).unwrap()),
    )
    .await
    .unwrap();
    assert!(matches!(
        uploaded(&wire, 10).await,
        Err(ProtocolError::EmptyChunk)
    ));
    let mut wire = Vec::new();
    write_message(&mut wire, &Response::Chunk(Chunk::new(vec![]).unwrap()))
        .await
        .unwrap();
    assert!(matches!(
        fetched(&wire, 10).await,
        Err(ProtocolError::EmptyChunk)
    ));
}

#[tokio::test]
async fn an_oversize_chunk_is_rejected() {
    let mut body = vec![4];
    body.extend(postcard::to_stdvec(&vec![0u8; CHUNK_LEN + 1]).unwrap());
    let wire = common::frame(&body);
    assert!(matches!(
        uploaded(&wire, (CHUNK_LEN + 1) as u64).await,
        Err(ProtocolError::Decode(_))
    ));
}

#[tokio::test]
async fn a_failing_sink_reports_an_io_error() {
    let result = receive_fetch(
        &mut Cursor::new(fetch_wire(&data(100)).await),
        &mut Broken(io::ErrorKind::StorageFull),
        100,
    )
    .await;
    assert!(matches!(result, Err(ProtocolError::Io(_))));
}

#[tokio::test]
async fn a_failing_writer_reports_an_io_error_when_sending() {
    assert!(matches!(
        send_upload(&mut Broken(io::ErrorKind::BrokenPipe), &data(10)).await,
        Err(ProtocolError::Io(_))
    ));
    assert!(matches!(
        send_fetch(&mut Broken(io::ErrorKind::BrokenPipe), &data(10)).await,
        Err(ProtocolError::Io(_))
    ));
}

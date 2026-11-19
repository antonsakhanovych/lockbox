use std::io::Cursor;

mod common;

use lockbox_protocol::chunk::CHUNK_LEN;
use lockbox_protocol::codec::{MAX_MESSAGE_LEN, read_message, write_message};
use lockbox_protocol::{Chunk, ProtocolError};

async fn encode(chunk: &Chunk) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_message(&mut bytes, chunk).await.unwrap();
    common::body(bytes)
}

async fn decode(bytes: &[u8]) -> Result<Chunk, ProtocolError> {
    read_message(&mut Cursor::new(common::frame(bytes))).await
}

#[test]
fn chunks_up_to_the_maximum_are_accepted() {
    for length in [0, 1, 1000, CHUNK_LEN - 1, CHUNK_LEN] {
        let chunk = Chunk::new(vec![7; length]).unwrap();
        assert_eq!(chunk.as_bytes().len(), length);
    }
}

#[test]
fn a_chunk_over_the_maximum_is_rejected() {
    assert!(matches!(
        Chunk::new(vec![0; CHUNK_LEN + 1]),
        Err(ProtocolError::ChunkTooLarge { len, max })
            if len == CHUNK_LEN + 1 && max == CHUNK_LEN
    ));
}

#[test]
fn the_bytes_come_back_unchanged() {
    let data: Vec<u8> = (0..=255).collect();
    let chunk = Chunk::new(data.clone()).unwrap();
    assert_eq!(chunk.as_bytes(), data);
    assert_eq!(chunk.into_bytes(), data);
}

#[tokio::test]
async fn a_chunk_round_trips_through_the_codec() {
    for length in [0, 1, 4096, CHUNK_LEN] {
        let chunk = Chunk::new(vec![0xAB; length]).unwrap();
        assert_eq!(decode(&encode(&chunk).await).await.unwrap(), chunk);
    }
}

#[tokio::test]
async fn on_the_wire_a_chunk_is_a_length_then_its_bytes() {
    let chunk = Chunk::new(vec![9, 8, 7]).unwrap();
    assert_eq!(encode(&chunk).await, [3, 9, 8, 7]);
}

#[tokio::test]
async fn an_oversize_chunk_is_rejected_when_decoding() {
    for length in [CHUNK_LEN + 1, 2 * CHUNK_LEN] {
        let bytes = postcard::to_stdvec(&vec![0u8; length]).unwrap();
        assert!(
            matches!(decode(&bytes).await, Err(ProtocolError::Decode(_))),
            "length {length}"
        );
    }
}

#[tokio::test]
async fn the_largest_chunk_fits_in_a_message_with_room_to_spare() {
    let bytes = encode(&Chunk::new(vec![0; CHUNK_LEN]).unwrap()).await;
    assert!(bytes.len() < MAX_MESSAGE_LEN / 2);
}

use std::io::{self, Cursor};
use std::pin::Pin;
use std::task::{Context, Poll};

mod common;

use lockbox_protocol::ProtocolError;
use lockbox_protocol::codec::{self, MAX_MESSAGE_LEN, read_message, write_message};
use lockbox_protocol::crypto::keys::generate_keypair;
use lockbox_protocol::crypto::sign::sign;
use lockbox_protocol::crypto::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
enum Message {
    Ping,
    Number(u32),
    Chunk {
        data: Vec<u8>,
    },
    Name(String),
    Signed {
        key: VerifyingKey,
        nonce: [u8; 32],
        signature: Signature,
    },
    Keys(Vec<VerifyingKey>),
}

fn signed_message() -> Message {
    let key = generate_keypair();
    Message::Signed {
        key: key.verifying_key(),
        nonce: [0x5A; 32],
        signature: sign(b"proof", &key),
    }
}

async fn encode(message: &Message) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_message(&mut bytes, message).await.unwrap();
    common::body(bytes)
}

async fn decode(bytes: &[u8]) -> Result<Message, ProtocolError> {
    read_message(&mut Cursor::new(common::frame(bytes))).await
}

struct OneByteAtATime<'a>(&'a [u8]);

impl AsyncRead for OneByteAtATime<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some((&byte, rest)) = self.0.split_first()
            && buf.remaining() > 0
        {
            buf.put_slice(&[byte]);
            self.0 = rest;
        }
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn every_kind_of_message_round_trips() {
    let messages = [
        Message::Ping,
        Message::Number(0xDEAD_BEEF),
        Message::Chunk { data: vec![] },
        Message::Chunk {
            data: (0..=255).collect(),
        },
        Message::Name("lockbox".to_string()),
        signed_message(),
    ];
    for message in messages {
        assert_eq!(decode(&encode(&message).await).await.unwrap(), message);
    }
}

#[tokio::test]
async fn the_wire_layout_is_a_kind_byte_then_the_fields() {
    assert_eq!(encode(&Message::Ping).await, [0]);
    assert_eq!(encode(&Message::Number(5)).await, [1, 5]);
    assert_eq!(encode(&Message::Number(300)).await, [1, 0xAC, 0x02]);
    assert_eq!(
        encode(&Message::Chunk { data: vec![9, 8] }).await,
        [2, 2, 9, 8]
    );
    assert_eq!(
        encode(&Message::Name("hi".to_string())).await,
        [3, 2, b'h', b'i']
    );
}

#[tokio::test]
async fn several_messages_are_read_in_order_from_one_stream() {
    let sent = [
        Message::Number(1),
        Message::Chunk {
            data: vec![1, 2, 3],
        },
        Message::Ping,
        Message::Name("last".to_string()),
    ];
    let mut bytes = Vec::new();
    for message in &sent {
        write_message(&mut bytes, message).await.unwrap();
    }
    let mut reader = Cursor::new(bytes);
    for expected in sent {
        assert_eq!(
            read_message::<Message, _>(&mut reader).await.unwrap(),
            expected
        );
    }
    assert!(matches!(
        read_message::<Message, _>(&mut reader).await,
        Err(ProtocolError::ConnectionClosed)
    ));
}

#[tokio::test]
async fn an_empty_stream_means_the_connection_closed() {
    assert!(matches!(
        read_message::<Message, _>(&mut Cursor::new(Vec::new())).await,
        Err(ProtocolError::ConnectionClosed)
    ));
}

#[tokio::test]
async fn a_stream_cut_inside_a_message_means_the_connection_closed() {
    let wire = common::frame(&encode(&Message::Chunk { data: vec![5; 20] }).await);
    for length in 0..wire.len() {
        assert!(
            matches!(
                read_message::<Message, _>(&mut Cursor::new(&wire[..length])).await,
                Err(ProtocolError::ConnectionClosed)
            ),
            "length {length}"
        );
    }
}

#[tokio::test]
async fn an_unknown_message_kind_is_a_decode_error() {
    assert!(matches!(decode(&[99]).await, Err(ProtocolError::Decode(_))));
}

#[tokio::test]
async fn invalid_text_is_a_decode_error() {
    assert!(matches!(
        decode(&[3, 2, 0xFF, 0xFE]).await,
        Err(ProtocolError::Decode(_))
    ));
}

#[tokio::test]
async fn a_message_over_the_limit_is_rejected_when_writing_and_nothing_is_written() {
    let message = Message::Chunk {
        data: vec![0; MAX_MESSAGE_LEN],
    };
    let mut out = Vec::new();
    let error = write_message(&mut out, &message).await.unwrap_err();
    assert!(matches!(
        error,
        ProtocolError::MessageTooLarge { len, max }
            if len > MAX_MESSAGE_LEN && max == MAX_MESSAGE_LEN
    ));
    assert!(out.is_empty());
}

#[tokio::test]
async fn a_message_over_the_limit_is_rejected_when_reading() {
    let wire = ((MAX_MESSAGE_LEN + 1) as u32).to_be_bytes();
    assert!(matches!(
        read_message::<Message, _>(&mut Cursor::new(wire)).await,
        Err(ProtocolError::MessageLimitExceeded { max }) if max == MAX_MESSAGE_LEN
    ));
}

#[tokio::test]
async fn a_huge_claimed_length_is_rejected_before_reading_the_body() {
    let wire = u32::MAX.to_be_bytes();
    assert!(matches!(
        read_message::<Message, _>(&mut Cursor::new(wire)).await,
        Err(ProtocolError::MessageLimitExceeded { .. })
    ));
}

#[tokio::test]
async fn the_length_prefix_is_four_big_endian_bytes_before_the_message() {
    let mut wire = Vec::new();
    write_message(&mut wire, &Message::Number(300))
        .await
        .unwrap();
    assert_eq!(wire, [0, 0, 0, 3, 1, 0xAC, 0x02]);
}

#[tokio::test]
async fn bytes_after_the_end_of_a_message_are_rejected() {
    assert!(matches!(
        decode(&[0, 0]).await,
        Err(ProtocolError::TrailingBytes)
    ));
}

#[tokio::test]
async fn a_zero_length_frame_is_a_decode_error() {
    assert!(matches!(decode(&[]).await, Err(ProtocolError::Decode(_))));
}

#[tokio::test]
async fn a_reader_that_returns_one_byte_at_a_time_still_works() {
    let message = Message::Chunk {
        data: vec![3; 1000],
    };
    let bytes = encode(&message).await;
    let read: Message = read_message(&mut OneByteAtATime(&common::frame(&bytes)))
        .await
        .unwrap();
    assert_eq!(read, message);
}

#[tokio::test]
async fn a_failing_writer_reports_an_io_error() {
    struct Broken;
    impl AsyncWrite for Broken {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    assert!(matches!(
        write_message(&mut Broken, &Message::Ping).await,
        Err(ProtocolError::Io(_))
    ));
}

#[tokio::test]
async fn a_message_just_under_the_limit_is_accepted() {
    let overhead = encode(&Message::Chunk { data: vec![] }).await.len() + 3;
    let message = Message::Chunk {
        data: vec![1; MAX_MESSAGE_LEN - overhead],
    };
    let bytes = encode(&message).await;
    assert!(bytes.len() <= MAX_MESSAGE_LEN);
    assert_eq!(decode(&bytes).await.unwrap(), message);
}

#[test]
fn encode_and_decode_round_trip_without_any_io() {
    let message = Message::Chunk { data: vec![7; 100] };
    let bytes = codec::encode(&message).unwrap();
    assert_eq!(codec::decode::<Message>(&bytes).unwrap(), message);
}

#[test]
fn encode_has_no_length_prefix() {
    assert_eq!(
        codec::encode(&Message::Number(300)).unwrap(),
        [1, 0xAC, 0x02]
    );
}

#[tokio::test]
async fn a_stream_frame_is_the_prefix_followed_by_encode() {
    let message = signed_message();
    let mut wire = Vec::new();
    write_message(&mut wire, &message).await.unwrap();
    assert_eq!(wire, common::frame(&codec::encode(&message).unwrap()));
}

#[test]
fn encode_rejects_a_message_over_the_limit() {
    let message = Message::Chunk {
        data: vec![0; MAX_MESSAGE_LEN],
    };
    assert!(matches!(
        codec::encode(&message),
        Err(ProtocolError::MessageTooLarge { max, .. }) if max == MAX_MESSAGE_LEN
    ));
}

#[test]
fn decode_rejects_bytes_over_the_limit() {
    assert!(matches!(
        codec::decode::<Message>(&vec![0; MAX_MESSAGE_LEN + 1]),
        Err(ProtocolError::MessageLimitExceeded { max }) if max == MAX_MESSAGE_LEN
    ));
}

#[test]
fn decode_rejects_trailing_bytes_and_empty_input() {
    assert!(matches!(
        codec::decode::<Message>(&[0, 0]),
        Err(ProtocolError::TrailingBytes)
    ));
    assert!(matches!(
        codec::decode::<Message>(&[]),
        Err(ProtocolError::Decode(_))
    ));
}

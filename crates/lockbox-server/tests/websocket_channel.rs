use futures_util::{SinkExt, StreamExt};
use lockbox_protocol::chunk::CHUNK_LEN;
use lockbox_protocol::codec::{MAX_MESSAGE_LEN, encode};
use lockbox_protocol::{Chunk, ErrorCode, FileId, ProtocolError, Request, Response};
use lockbox_server::adapters::driving::WebSocketChannel;
use lockbox_server::core::ports::driving::{Channel, ChannelError};
use tokio::io::{DuplexStream, duplex};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{WebSocketStream, client_async};

type Client = WebSocketStream<DuplexStream>;

async fn pair() -> (WebSocketChannel<DuplexStream>, Client) {
    let (server, client) = duplex(2 * CHUNK_LEN);
    let (channel, client) = tokio::join!(
        WebSocketChannel::accept(server),
        client_async("ws://lockbox.test", client)
    );
    (channel.unwrap(), client.unwrap().0)
}

fn binary(bytes: Vec<u8>) -> Message {
    Message::Binary(bytes.into())
}

#[tokio::test]
async fn a_binary_frame_is_one_request() {
    let (mut channel, mut client) = pair().await;
    client
        .send(binary(encode(&Request::BeginUpload).unwrap()))
        .await
        .unwrap();

    assert_eq!(channel.receive().await.unwrap(), Some(Request::BeginUpload));
}

#[tokio::test]
async fn the_frame_carries_no_length_prefix() {
    let (mut channel, mut client) = pair().await;
    let response = Response::Uploaded {
        file_id: FileId::random(),
        expires_at: 7,
    };

    channel.send(&response).await.unwrap();

    let Some(Ok(Message::Binary(bytes))) = client.next().await else {
        panic!("expected a binary frame");
    };
    assert_eq!(bytes.as_ref(), encode(&response).unwrap().as_slice());
}

#[tokio::test]
async fn requests_arrive_in_order() {
    let (mut channel, mut client) = pair().await;
    let file_id = FileId::random();
    client
        .send(binary(encode(&Request::BeginUpload).unwrap()))
        .await
        .unwrap();
    client
        .send(binary(encode(&Request::BeginFetch { file_id }).unwrap()))
        .await
        .unwrap();

    assert_eq!(channel.receive().await.unwrap(), Some(Request::BeginUpload));
    assert_eq!(
        channel.receive().await.unwrap(),
        Some(Request::BeginFetch { file_id })
    );
}

#[tokio::test]
async fn a_full_size_chunk_round_trips() {
    let (mut channel, mut client) = pair().await;
    let chunk = Chunk::new(vec![0xAB; CHUNK_LEN]).unwrap();

    client
        .send(binary(
            encode(&Request::UploadChunk(chunk.clone())).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(
        channel.receive().await.unwrap(),
        Some(Request::UploadChunk(chunk.clone()))
    );

    let response = Response::Chunk(chunk);
    let (sent, received) = tokio::join!(channel.send(&response), client.next());
    sent.unwrap();
    let Some(Ok(Message::Binary(bytes))) = received else {
        panic!("expected a binary frame");
    };
    assert_eq!(bytes.as_ref(), encode(&response).unwrap().as_slice());
}

#[tokio::test]
async fn a_close_frame_ends_the_stream() {
    let (mut channel, mut client) = pair().await;
    client.close(None).await.unwrap();

    assert_eq!(channel.receive().await.unwrap(), None);
}

#[tokio::test]
async fn a_dropped_connection_ends_the_stream() {
    let (mut channel, client) = pair().await;
    drop(client);

    assert!(matches!(
        channel.receive().await,
        Ok(None) | Err(ChannelError::Io(_))
    ));
}

#[tokio::test]
async fn pings_are_skipped() {
    let (mut channel, mut client) = pair().await;
    client
        .send(Message::Ping(vec![1, 2, 3].into()))
        .await
        .unwrap();
    client
        .send(binary(encode(&Request::BeginUpload).unwrap()))
        .await
        .unwrap();

    assert_eq!(channel.receive().await.unwrap(), Some(Request::BeginUpload));
}

#[tokio::test]
async fn a_text_frame_is_a_codec_error() {
    let (mut channel, mut client) = pair().await;
    client.send(Message::Text("hello".into())).await.unwrap();

    let error = channel.receive().await.unwrap_err();
    assert!(matches!(
        error,
        ChannelError::Codec(ProtocolError::UnexpectedMessage)
    ));
    assert_eq!(ErrorCode::from(&error), ErrorCode::InvalidRequest);
}

#[tokio::test]
async fn garbage_is_a_codec_error() {
    let (mut channel, mut client) = pair().await;
    client.send(binary(vec![0xFF; 16])).await.unwrap();

    let error = channel.receive().await.unwrap_err();
    assert!(matches!(error, ChannelError::Codec(_)));
    assert_eq!(ErrorCode::from(&error), ErrorCode::InvalidRequest);
}

#[tokio::test]
async fn trailing_bytes_are_rejected() {
    let (mut channel, mut client) = pair().await;
    let mut bytes = encode(&Request::BeginUpload).unwrap();
    bytes.push(0);
    client.send(binary(bytes)).await.unwrap();

    let error = channel.receive().await.unwrap_err();
    assert!(matches!(
        error,
        ChannelError::Codec(ProtocolError::TrailingBytes)
    ));
}

#[tokio::test]
async fn an_oversized_frame_is_rejected() {
    let (mut channel, mut client) = pair().await;
    let received = tokio::select! {
        received = channel.receive() => received,
        _ = client.send(binary(vec![0; MAX_MESSAGE_LEN + 1])) => panic!("the frame was not rejected"),
    };

    let error = received.unwrap_err();
    assert!(matches!(
        error,
        ChannelError::Codec(ProtocolError::MessageLimitExceeded { .. })
    ));
    assert_eq!(ErrorCode::from(&error), ErrorCode::InvalidRequest);
}

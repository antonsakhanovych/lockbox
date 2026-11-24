use lockbox_protocol::chunk::CHUNK_LEN;
use lockbox_protocol::codec::{MAX_MESSAGE_LEN, encode, read_message, write_message};
use lockbox_protocol::{Chunk, ErrorCode, FileId, ProtocolError, Request, Response};
use lockbox_server::adapters::driving::StreamChannel;
use lockbox_server::core::ports::driving::{Channel, ChannelError};
use tokio::io::{AsyncWriteExt, DuplexStream, duplex};
use tokio::net::{TcpListener, TcpStream};

fn pair() -> (StreamChannel<DuplexStream>, DuplexStream) {
    let (server, client) = duplex(64 * 1024);
    (StreamChannel::new(server), client)
}

async fn raw_frame(client: &mut DuplexStream, len: u32, body: &[u8]) {
    client.write_all(&len.to_be_bytes()).await.unwrap();
    client.write_all(body).await.unwrap();
    client.flush().await.unwrap();
}

async fn echo<C>(channel: &mut C)
where
    C: Channel,
{
    while let Some(request) = channel.receive().await.unwrap() {
        let response = match request {
            Request::BeginFetch { file_id } => Response::Uploaded {
                file_id,
                expires_at: 7,
            },
            _ => Response::Error(ErrorCode::UnexpectedMessage),
        };
        channel.send(&response).await.unwrap();
    }
}

#[tokio::test]
async fn a_request_from_the_client_is_received() {
    let (mut channel, mut client) = pair();
    write_message(&mut client, &Request::BeginUpload)
        .await
        .unwrap();
    assert_eq!(channel.receive().await.unwrap(), Some(Request::BeginUpload));
}

#[tokio::test]
async fn a_request_with_fields_is_received_intact() {
    let (mut channel, mut client) = pair();
    let file_id = FileId::random();
    write_message(&mut client, &Request::BeginDelete { file_id })
        .await
        .unwrap();
    assert_eq!(
        channel.receive().await.unwrap(),
        Some(Request::BeginDelete { file_id })
    );
}

#[tokio::test]
async fn a_full_size_chunk_is_received() {
    let (server, mut client) = duplex(2 * CHUNK_LEN);
    let mut channel = StreamChannel::new(server);
    let chunk = Chunk::new(vec![7; CHUNK_LEN]).unwrap();
    let request = Request::UploadChunk(chunk);
    write_message(&mut client, &request).await.unwrap();
    assert_eq!(channel.receive().await.unwrap(), Some(request));
}

#[tokio::test]
async fn requests_are_received_in_the_order_they_were_sent() {
    let (mut channel, mut client) = pair();
    let first = FileId::random();
    let second = FileId::random();
    write_message(&mut client, &Request::BeginFetch { file_id: first })
        .await
        .unwrap();
    write_message(&mut client, &Request::BeginFetch { file_id: second })
        .await
        .unwrap();
    assert_eq!(
        channel.receive().await.unwrap(),
        Some(Request::BeginFetch { file_id: first })
    );
    assert_eq!(
        channel.receive().await.unwrap(),
        Some(Request::BeginFetch { file_id: second })
    );
}

#[tokio::test]
async fn a_response_is_sent_in_the_wire_format() {
    let (mut channel, mut client) = pair();
    let response = Response::Uploaded {
        file_id: FileId::random(),
        expires_at: 42,
    };
    channel.send(&response).await.unwrap();
    let received: Response = read_message(&mut client).await.unwrap();
    assert_eq!(received, response);
}

#[tokio::test]
async fn responses_are_sent_in_order() {
    let (mut channel, mut client) = pair();
    channel.send(&Response::ReadyForUpload).await.unwrap();
    channel.send(&Response::Deleted).await.unwrap();
    assert_eq!(
        read_message::<Response, _>(&mut client).await.unwrap(),
        Response::ReadyForUpload
    );
    assert_eq!(
        read_message::<Response, _>(&mut client).await.unwrap(),
        Response::Deleted
    );
}

#[tokio::test]
async fn a_closed_connection_is_none() {
    let (mut channel, client) = pair();
    drop(client);
    assert_eq!(channel.receive().await.unwrap(), None);
}

#[tokio::test]
async fn requests_sent_before_the_close_are_still_received() {
    let (mut channel, mut client) = pair();
    write_message(&mut client, &Request::BeginUpload)
        .await
        .unwrap();
    drop(client);
    assert_eq!(channel.receive().await.unwrap(), Some(Request::BeginUpload));
    assert_eq!(channel.receive().await.unwrap(), None);
}

#[tokio::test]
async fn a_close_in_the_middle_of_a_message_is_none() {
    let (mut channel, mut client) = pair();
    let bytes = encode(&Request::BeginUpload).unwrap();
    client
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .await
        .unwrap();
    drop(client);
    assert_eq!(channel.receive().await.unwrap(), None);
}

#[tokio::test]
async fn a_frame_longer_than_the_limit_is_malformed() {
    let (mut channel, mut client) = pair();
    client
        .write_all(&(MAX_MESSAGE_LEN as u32 + 1).to_be_bytes())
        .await
        .unwrap();
    assert!(matches!(
        channel.receive().await,
        Err(ChannelError::Codec(
            ProtocolError::MessageLimitExceeded { .. }
        ))
    ));
}

#[tokio::test]
async fn a_body_that_is_not_a_request_is_malformed() {
    let (mut channel, mut client) = pair();
    raw_frame(&mut client, 3, &[0xFF, 0xFF, 0xFF]).await;
    assert!(matches!(
        channel.receive().await,
        Err(ChannelError::Codec(ProtocolError::Decode(_)))
    ));
}

#[tokio::test]
async fn an_empty_frame_is_malformed() {
    let (mut channel, mut client) = pair();
    raw_frame(&mut client, 0, &[]).await;
    assert!(matches!(
        channel.receive().await,
        Err(ChannelError::Codec(ProtocolError::Decode(_)))
    ));
}

#[tokio::test]
async fn bytes_after_the_end_of_a_message_are_malformed() {
    let (mut channel, mut client) = pair();
    let mut body = encode(&Request::BeginUpload).unwrap();
    body.push(0);
    raw_frame(&mut client, body.len() as u32, &body).await;
    assert!(matches!(
        channel.receive().await,
        Err(ChannelError::Codec(ProtocolError::TrailingBytes))
    ));
}

#[tokio::test]
async fn a_valid_message_is_still_received_after_a_malformed_frame_was_consumed() {
    let (mut channel, mut client) = pair();
    raw_frame(&mut client, 3, &[0xFF, 0xFF, 0xFF]).await;
    write_message(&mut client, &Request::BeginUpload)
        .await
        .unwrap();
    assert!(channel.receive().await.is_err());
    assert_eq!(channel.receive().await.unwrap(), Some(Request::BeginUpload));
}

#[tokio::test]
async fn sending_to_a_closed_connection_is_an_io_error() {
    let (mut channel, client) = pair();
    drop(client);
    assert!(matches!(
        channel.send(&Response::Deleted).await,
        Err(ChannelError::Io(_))
    ));
}

#[tokio::test]
async fn a_generic_handler_works_over_the_channel() {
    let (mut channel, mut client) = pair();
    let file_id = FileId::random();
    let handler = tokio::spawn(async move { echo(&mut channel).await });
    write_message(&mut client, &Request::BeginFetch { file_id })
        .await
        .unwrap();
    let reply: Response = read_message(&mut client).await.unwrap();
    assert_eq!(
        reply,
        Response::Uploaded {
            file_id,
            expires_at: 7
        }
    );
    write_message(&mut client, &Request::BeginUpload)
        .await
        .unwrap();
    let reply: Response = read_message(&mut client).await.unwrap();
    assert_eq!(reply, Response::Error(ErrorCode::UnexpectedMessage));
    drop(client);
    handler.await.unwrap();
}

#[tokio::test]
async fn it_works_over_a_real_tcp_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut channel = StreamChannel::new(stream);
        echo(&mut channel).await;
    });
    let mut client = TcpStream::connect(address).await.unwrap();
    let file_id = FileId::random();
    write_message(&mut client, &Request::BeginFetch { file_id })
        .await
        .unwrap();
    let reply: Response = read_message(&mut client).await.unwrap();
    assert_eq!(
        reply,
        Response::Uploaded {
            file_id,
            expires_at: 7
        }
    );
    drop(client);
    server.await.unwrap();
}

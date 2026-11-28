use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use lockbox_protocol::codec::{decode, encode, read_message, write_message};
use lockbox_protocol::{Request, Response};
use lockbox_server::adapters::driven::{DiskStore, SystemClock};
use lockbox_server::app::assemble;
use lockbox_server::transport::{tcp, websocket};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::time::timeout;
use tokio_tungstenite::client_async;
use tokio_tungstenite::tungstenite::Message;

async fn stopped(mut stop: watch::Receiver<bool>) {
    let _ = stop.wait_for(|stopped| *stopped).await;
}

#[tokio::test]
async fn tcp_and_websocket_are_served_at_the_same_time() {
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_address = tcp_listener.local_addr().unwrap();
    let ws_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ws_address = ws_listener.local_addr().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(DiskStore::new(dir.path().to_path_buf()).await.unwrap());
    let assembled = assemble(Arc::new(SystemClock), store);
    let (stop, stop_signal) = watch::channel(false);
    let tcp_server = tokio::spawn(tcp::serve(
        tcp_listener,
        assembled.services.clone(),
        stopped(stop_signal.clone()),
    ));
    let ws_server = tokio::spawn(websocket::serve(
        ws_listener,
        assembled.services,
        stopped(stop_signal),
    ));

    let mut tcp_client = TcpStream::connect(tcp_address).await.unwrap();
    write_message(&mut tcp_client, &Request::BeginUpload)
        .await
        .unwrap();
    let tcp_response: Response = read_message(&mut tcp_client).await.unwrap();
    assert!(matches!(tcp_response, Response::Challenge(_)));

    let stream = TcpStream::connect(ws_address).await.unwrap();
    let (mut ws_client, _) = client_async("ws://lockbox.test", stream).await.unwrap();
    ws_client
        .send(Message::Binary(
            encode(&Request::BeginUpload).unwrap().into(),
        ))
        .await
        .unwrap();
    let Some(Ok(Message::Binary(bytes))) = ws_client.next().await else {
        panic!("expected a binary frame");
    };
    let ws_response: Response = decode(&bytes).unwrap();
    assert!(matches!(ws_response, Response::Challenge(_)));

    stop.send(true).unwrap();
    for server in [tcp_server, ws_server] {
        let result = timeout(Duration::from_secs(5), server).await;
        assert!(result.expect("server did not stop").unwrap().is_ok());
    }
}

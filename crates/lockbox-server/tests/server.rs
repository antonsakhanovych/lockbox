use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use lockbox_protocol::codec::{read_message, write_message};
use lockbox_protocol::{Request, Response};
use lockbox_server::adapters::driven::{DiskStore, SystemClock};
use lockbox_server::app::assemble;
use lockbox_server::transport::tcp::serve;
use lockbox_server::{Config, TransportKind};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time::timeout;

#[test]
fn the_default_config_listens_on_localhost() {
    let config = Config::parse_from(["lockbox-server"]);

    assert_eq!(config.listen_addr.to_string(), "127.0.0.1:5625");
    assert_eq!(config.storage_dir.to_str(), Some("lockbox-data"));
}

#[test]
fn the_config_can_be_overridden() {
    let config = Config::parse_from([
        "lockbox-server",
        "--listen-addr",
        "0.0.0.0:9000",
        "--storage-dir",
        "/tmp/files",
    ]);

    assert_eq!(config.listen_addr.to_string(), "0.0.0.0:9000");
    assert_eq!(config.storage_dir.to_str(), Some("/tmp/files"));
}

#[test]
fn an_invalid_listen_address_is_rejected() {
    assert!(Config::try_parse_from(["lockbox-server", "--listen-addr", "nonsense"]).is_err());
}

#[tokio::test]
async fn the_server_accepts_connections_and_stops_on_shutdown() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = oneshot::channel::<()>();
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(DiskStore::new(dir.path().to_path_buf()).await.unwrap());
    let assembled = assemble(Arc::new(SystemClock), store);
    let server = tokio::spawn(serve(listener, assembled.services, async {
        let _ = stopped.await;
    }));

    for _ in 0..2 {
        let mut client = TcpStream::connect(address).await.unwrap();

        write_message(&mut client, &Request::BeginUpload)
            .await
            .unwrap();
        let response: Response = read_message(&mut client).await.unwrap();
        assert!(matches!(response, Response::Challenge(_)));
    }

    stop.send(()).unwrap();
    let result = timeout(Duration::from_secs(5), server).await;

    assert!(result.expect("server did not stop").unwrap().is_ok());
}

#[tokio::test]
async fn the_server_stops_accepting_after_shutdown() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(DiskStore::new(dir.path().to_path_buf()).await.unwrap());
    let assembled = assemble(Arc::new(SystemClock), store);
    let server = tokio::spawn(serve(listener, assembled.services, async {}));

    timeout(Duration::from_secs(5), server)
        .await
        .expect("server did not stop")
        .unwrap()
        .unwrap();

    assert!(TcpStream::connect(address).await.is_err());
}

#[tokio::test]
async fn tcp_shutdown_closes_sessions_stops_expiry_and_removes_finished_and_partial_files() {
    use lockbox_protocol::crypto::envelope::Envelope;
    use lockbox_protocol::crypto::keys::generate_keypair;
    use lockbox_protocol::transfer::{receive_fetch, send_upload};
    use lockbox_protocol::{Chunk, FileHeader, SignedRequest};
    use lockbox_server::core::ports::driven::Clock;

    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(DiskStore::new(dir.path().to_path_buf()).await.unwrap());
    let assembled = assemble(Arc::new(SystemClock), store);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (result, ()) = tokio::join!(
            serve(listener, assembled.services, async {
                stopped.await.unwrap();
            }),
            assembled.worker.run(),
        );

        result
    });

    let key = generate_keypair();
    let (envelope, ciphertext) =
        Envelope::encrypt_to_recipients(b"over TCP", &[key.verifying_key()])
            .unwrap()
            .into_parts();
    let header = FileHeader {
        envelope,
        ciphertext_len: ciphertext.len() as u64,
        expires_at: SystemClock.now() + 300,
    };
    let mut client = TcpStream::connect(address).await.unwrap();
    let mut file_id = None;

    for finish in [true, false] {
        write_message(&mut client, &Request::BeginUpload)
            .await
            .unwrap();
        let Response::Challenge(challenge) = read_message(&mut client).await.unwrap() else {
            panic!("expected challenge")
        };
        write_message(
            &mut client,
            &Request::Upload {
                proof: SignedRequest::answer(&challenge, &key),
                header: header.clone(),
            },
        )
        .await
        .unwrap();
        assert_eq!(
            read_message::<Response, _>(&mut client).await.unwrap(),
            Response::ReadyForUpload
        );

        if finish {
            send_upload(&mut client, &ciphertext).await.unwrap();
            let Response::Uploaded { file_id: id, .. } = read_message(&mut client).await.unwrap()
            else {
                panic!("expected uploaded")
            };
            file_id = Some(id);
        } else {
            write_message(
                &mut client,
                &Request::UploadChunk(Chunk::new(vec![1]).unwrap()),
            )
            .await
            .unwrap();
        }
    }

    let mut reader = TcpStream::connect(address).await.unwrap();

    write_message(
        &mut reader,
        &Request::BeginFetch {
            file_id: file_id.unwrap(),
        },
    )
    .await
    .unwrap();
    let Response::Challenge(challenge) = read_message(&mut reader).await.unwrap() else {
        panic!("expected challenge")
    };
    write_message(
        &mut reader,
        &Request::Fetch(SignedRequest::answer(&challenge, &key)),
    )
    .await
    .unwrap();
    let Response::FetchReady(header) = read_message(&mut reader).await.unwrap() else {
        panic!("expected fetch")
    };
    let mut bytes = Vec::new();
    receive_fetch(&mut reader, &mut bytes, header.ciphertext_len)
        .await
        .unwrap();
    assert_eq!(header.recipient.decrypt(&key, &bytes).unwrap(), b"over TCP");
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);

    stop.send(()).unwrap();
    timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);

    for mut stream in [client, reader] {
        assert!(matches!(
            timeout(
                Duration::from_secs(5),
                read_message::<Response, _>(&mut stream)
            )
            .await
            .unwrap(),
            Err(lockbox_protocol::ProtocolError::ConnectionClosed)
        ));
    }
}

#[test]
fn both_transports_are_served_by_default() {
    let config = Config::parse_from(["lockbox-server"]);

    assert!(config.serves(TransportKind::Tcp));
    assert!(config.serves(TransportKind::WebSocket));
    assert_eq!(config.ws_listen_addr.to_string(), "127.0.0.1:5626");
}

#[test]
fn a_single_transport_can_be_selected() {
    let tcp = Config::parse_from(["lockbox-server", "--transport", "tcp"]);
    let ws = Config::parse_from(["lockbox-server", "--transport", "ws"]);

    assert!(tcp.serves(TransportKind::Tcp) && !tcp.serves(TransportKind::WebSocket));
    assert!(ws.serves(TransportKind::WebSocket) && !ws.serves(TransportKind::Tcp));
}

#[test]
fn transports_can_be_listed_together() {
    let config = Config::parse_from(["lockbox-server", "--transport", "tcp,ws"]);

    assert!(config.serves(TransportKind::Tcp));
    assert!(config.serves(TransportKind::WebSocket));
}

#[test]
fn an_unknown_transport_is_rejected() {
    assert!(Config::try_parse_from(["lockbox-server", "--transport", "carrier-pigeon"]).is_err());
}

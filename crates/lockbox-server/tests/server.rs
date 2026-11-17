use std::time::Duration;

use clap::Parser;
use lockbox_server::Config;
use lockbox_server::transport::tcp::serve;
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
    let server = tokio::spawn(serve(listener, async {
        let _ = stopped.await;
    }));

    TcpStream::connect(address).await.unwrap();
    TcpStream::connect(address).await.unwrap();

    stop.send(()).unwrap();
    let result = timeout(Duration::from_secs(5), server).await;

    assert!(result.expect("server did not stop").unwrap().is_ok());
}

#[tokio::test]
async fn the_server_stops_accepting_after_shutdown() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(serve(listener, async {}));

    timeout(Duration::from_secs(5), server)
        .await
        .expect("server did not stop")
        .unwrap()
        .unwrap();

    assert!(TcpStream::connect(address).await.is_err());
}

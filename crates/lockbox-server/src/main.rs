use clap::Parser;
use lockbox_server::adapters::driven::{DiskStore, SystemClock};
use lockbox_server::app::{Assembled, assemble};
use lockbox_server::transport::{tcp, websocket};
use lockbox_server::{Config, Result, TransportKind};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let config = Config::parse();
    info!(storage_dir = %config.storage_dir.display(), "starting");

    let tcp_listener = match config.serves(TransportKind::Tcp) {
        true => Some(TcpListener::bind(config.listen_addr).await?),
        false => None,
    };
    let ws_listener = match config.serves(TransportKind::WebSocket) {
        true => Some(TcpListener::bind(config.ws_listen_addr).await?),
        false => None,
    };

    let store = Arc::new(DiskStore::new(config.storage_dir).await?);
    let Assembled { services, worker } = assemble(Arc::new(SystemClock), store);

    let shutdown = CancellationToken::new();
    tokio::spawn(cancel_on_ctrl_c(shutdown.clone()));

    let tcp_serve = {
        let services = services.clone();
        let shutdown = shutdown.clone();
        async move {
            match tcp_listener {
                Some(listener) => tcp::serve(listener, services, shutdown.cancelled_owned()).await,
                None => Ok(()),
            }
        }
    };
    let ws_serve = {
        let shutdown = shutdown.clone();
        async move {
            match ws_listener {
                Some(listener) => {
                    websocket::serve(listener, services, shutdown.cancelled_owned()).await
                }
                None => Ok(()),
            }
        }
    };

    let (tcp_result, ws_result, ()) = tokio::join!(tcp_serve, ws_serve, worker.run());

    tcp_result.and(ws_result)
}

async fn cancel_on_ctrl_c(shutdown: CancellationToken) {
    if let Err(error) = tokio::signal::ctrl_c().await {
        warn!(%error, "could not listen for Ctrl+C");
    }
    shutdown.cancel();
}

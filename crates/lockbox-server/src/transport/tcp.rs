use std::future::Future;

use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tracing::{info, warn};

use crate::error::Result;

/// Accepts connections on `listener` until `shutdown` completes.
/// Each connection runs in a separate task. Open connections are dropped on shutdown.
pub async fn serve(listener: TcpListener, handle_shutdown: impl Future<Output = ()>) -> Result<()> {
    info!(address = %listener.local_addr()?, "listening");

    tokio::pin!(handle_shutdown);

    let mut connections = JoinSet::new();

    loop {
        tokio::select! {
            () = &mut handle_shutdown => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, peer)) => {
                    info!(%peer, "connection opened");
                    connections.spawn(handle_connection(stream));
                }
                Err(error) => warn!(%error, "failed to accept a connection"),
            },
            Some(_) = connections.join_next() => {}
        }
    }

    info!("shutting down");

    Ok(())
}

async fn handle_connection(_stream: TcpStream) {
    todo!()
}

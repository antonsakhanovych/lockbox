use std::future::Future;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tracing::{info, warn};

use crate::adapters::driving::StreamChannel;
use crate::app::{Ports, Services};
use crate::error::Result;
use crate::session::Session;

/// Accepts connections on `listener` until `shutdown` completes.
/// Each connection runs in a separate task. Open connections are dropped on shutdown.
pub async fn serve<P: Ports + 'static>(
    listener: TcpListener,
    services: Arc<Services<P>>,
    handle_shutdown: impl Future<Output = ()>,
) -> Result<()> {
    info!(address = %listener.local_addr()?, "listening");

    tokio::pin!(handle_shutdown);

    let mut connections = JoinSet::new();

    loop {
        tokio::select! {
            () = &mut handle_shutdown => break,

            accepted = listener.accept() => match accepted {
                Ok((stream, peer)) => {
                    info!(%peer, "connection opened");

                    let session = Session::new(services.clone(), StreamChannel::new(stream));

                    connections.spawn(async move {
                        if let Err(error) = session.run().await {
                            warn!(%peer, %error, "session failed");
                        }

                        info!(%peer, "connection closed");
                    });
                }
                Err(error) => warn!(%error, "failed to accept a connection"),
            },

            Some(result) = connections.join_next() => {
                if let Err(error) = result {
                    warn!(%error, "connection task failed");
                }
            }
        }
    }

    info!("shutting down");
    connections.shutdown().await;

    Ok(())
}

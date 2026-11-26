pub mod tcp;
pub mod websocket;

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::{info, warn};

use crate::app::{Ports, Services};
use crate::core::ports::driving::{Channel, ChannelError};
use crate::error::Result;
use crate::session::Session;

const SETUP_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) async fn serve<P, C, F, Fut>(
    name: &'static str,
    listener: TcpListener,
    services: Arc<Services<P>>,
    handle_shutdown: impl Future<Output = ()>,
    open: F,
) -> Result<()>
where
    P: Ports + 'static,
    C: Channel + Send + 'static,
    F: Fn(TcpStream) -> Fut,
    Fut: Future<Output = std::result::Result<C, ChannelError>> + Send + 'static,
{
    info!(transport = name, address = %listener.local_addr()?, "listening");

    tokio::pin!(handle_shutdown);

    let mut connections = JoinSet::new();

    loop {
        tokio::select! {
            () = &mut handle_shutdown => break,

            accepted = listener.accept() => match accepted {
                Ok((stream, peer)) => {
                    info!(transport = name, %peer, "connection opened");

                    let services = services.clone();
                    let opening = open(stream);

                    connections.spawn(run_connection(name, peer, services, opening));
                }
                Err(error) => warn!(transport = name, %error, "failed to accept a connection"),
            },

            Some(result) = connections.join_next() => {
                if let Err(error) = result {
                    warn!(transport = name, %error, "connection task failed");
                }
            }
        }
    }

    info!(transport = name, "shutting down");
    connections.shutdown().await;

    Ok(())
}

async fn run_connection<P, C>(
    name: &'static str,
    peer: SocketAddr,
    services: Arc<Services<P>>,
    opening: impl Future<Output = std::result::Result<C, ChannelError>>,
) where
    P: Ports + 'static,
    C: Channel + Send + 'static,
{
    match timeout(SETUP_TIMEOUT, opening).await {
        Ok(Ok(channel)) => {
            if let Err(error) = Session::new(services, channel).run().await {
                warn!(transport = name, %peer, %error, "session failed");
            }
        }
        Ok(Err(error)) => warn!(transport = name, %peer, %error, "connection setup failed"),
        Err(_) => warn!(transport = name, %peer, "connection setup timed out"),
    }

    info!(transport = name, %peer, "connection closed");
}

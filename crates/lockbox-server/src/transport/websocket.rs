use std::future::Future;
use std::sync::Arc;

use tokio::net::TcpListener;

use crate::adapters::driving::WebSocketChannel;
use crate::app::{Ports, Services};
use crate::error::Result;

pub async fn serve<P: Ports + 'static>(
    listener: TcpListener,
    services: Arc<Services<P>>,
    handle_shutdown: impl Future<Output = ()>,
) -> Result<()> {
    super::serve(
        "ws",
        listener,
        services,
        handle_shutdown,
        WebSocketChannel::accept,
    )
    .await
}

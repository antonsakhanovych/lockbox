use std::future::{self, Future};
use std::sync::Arc;

use tokio::net::TcpListener;

use crate::adapters::driving::StreamChannel;
use crate::app::{Ports, Services};
use crate::error::Result;

pub async fn serve<P: Ports + 'static>(
    listener: TcpListener,
    services: Arc<Services<P>>,
    handle_shutdown: impl Future<Output = ()>,
) -> Result<()> {
    super::serve("tcp", listener, services, handle_shutdown, |stream| {
        future::ready(Ok(StreamChannel::new(stream)))
    })
    .await
}

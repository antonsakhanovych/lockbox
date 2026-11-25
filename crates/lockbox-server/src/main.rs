use clap::Parser;
use lockbox_server::adapters::driven::{DiskStore, SystemClock};
use lockbox_server::app::{Assembled, assemble};
use lockbox_server::transport::tcp;
use lockbox_server::{Config, Result};
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let config = Config::parse();
    info!(storage_dir = %config.storage_dir.display(), "starting");

    let listener = TcpListener::bind(config.listen_addr).await?;
    let store = Arc::new(DiskStore::new(config.storage_dir).await?);
    let Assembled { services, worker } = assemble(Arc::new(SystemClock), store);

    let (result, ()) = tokio::join!(
        tcp::serve(listener, services, handle_shutdown()),
        worker.run(),
    );

    result
}

async fn handle_shutdown() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        warn!(%error, "could not listen for Ctrl+C");
    }
}

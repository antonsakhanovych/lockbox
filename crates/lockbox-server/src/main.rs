use clap::Parser;
use lockbox_server::transport::tcp;
use lockbox_server::{Config, Result};
use tokio::net::TcpListener;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let config = Config::parse();
    info!(storage_dir = %config.storage_dir.display(), "starting");

    let listener = TcpListener::bind(config.listen_addr).await?;

    tcp::serve(listener, handle_shutdown()).await
}

async fn handle_shutdown() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        warn!(%error, "could not listen for Ctrl+C");
    }
}

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;

/// Command line options for the server
#[derive(Clone, Debug, Parser)]
#[command(version, about = "Lockbox server")]
pub struct Config {
    /// Address to listen on
    #[arg(long, default_value = "127.0.0.1:5625")] // 5625 = LOCK on keypad 😎
    pub listen_addr: SocketAddr,

    /// Folder for stored files
    #[arg(long, default_value = "lockbox-data")]
    pub storage_dir: PathBuf,
}

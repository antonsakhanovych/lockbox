use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, ValueEnum};

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum TransportKind {
    Tcp,
    #[value(name = "ws")]
    WebSocket,
}

#[derive(Clone, Debug, Parser)]
#[command(version, about = "Lockbox server")]
pub struct Config {
    #[arg(long, value_enum, value_delimiter = ',', default_value = "tcp,ws")]
    pub transport: Vec<TransportKind>,

    #[arg(long, default_value = "127.0.0.1:5625")]
    pub listen_addr: SocketAddr,

    #[arg(long, default_value = "127.0.0.1:5626")]
    pub ws_listen_addr: SocketAddr,

    #[arg(long, default_value = "lockbox-data")]
    pub storage_dir: PathBuf,
}

impl Config {
    pub fn serves(&self, kind: TransportKind) -> bool {
        self.transport.contains(&kind)
    }
}

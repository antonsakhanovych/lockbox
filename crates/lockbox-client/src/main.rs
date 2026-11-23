use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
 
use clap::{Args, Parser, Subcommand};
use lockbox_protocol::FileId;
 
#[derive(Parser)]
#[command(version, about = "Short-lived encrypted file sharing")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
 
#[derive(Args)]
struct Remote {
    #[arg(long)]
    server: SocketAddr,
    #[arg(long)]
    key: PathBuf,
}
 
#[derive(Subcommand)]
enum Command {
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    Upload {
        file: PathBuf,
        #[arg(long = "to", required = true)]
        recipients: Vec<PathBuf>,
        #[arg(long)]
        lifetime: u64,
        #[command(flatten)]
        remote: Remote,
    },
    Fetch {
        id: FileId,
        #[arg(long)]
        output: PathBuf,
        #[command(flatten)]
        remote: Remote,
    },
    Delete {
        id: FileId,
        #[command(flatten)]
        remote: Remote,
    },
}
 
#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}
 
fn run(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Command::Keygen { .. } => todo!(),
        Command::Upload { .. } => todo!(),
        Command::Fetch { .. } => todo!(),
        Command::Delete { .. } => todo!(),
    }
}
 
fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("lockbox: {error}");
            ExitCode::FAILURE
        }
    }
}
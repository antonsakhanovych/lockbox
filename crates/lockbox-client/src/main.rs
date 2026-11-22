
use clap::{Parser, Subcommand};
use std::error::Error;

mod errors;
use errors::CliError;

// convert standard file errors into CliError.
impl From<std::io::Error> for CliError {
    fn from(err: std::io::Error) -> Self {
        CliError::Io(err)
    }
}

// tell clap to be able to display custom error types
impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::Io(err) => write!(f, "File error: {}", err),
        }
    }
}

impl Error for CliError {}


// root cli
#[derive(Parser)]
#[command(
    name = "lockbox",
    version = "0.1.0",
    about = "Short-lived encrypted file sharing"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}



#[derive(Subcommand)]
enum Commands {

    //generate a new key pair
    Keygen {
        // output path for private key
        #[arg(long)]
        private: String,

        //output path for public key
        #[arg(long)]
        public: String,
    },

    //encrypt and upload a file
    Upload {
        // file to upload
        #[arg(long)]
        file: String,

        //recipient public key file (can be repeated)
        #[arg(long, required = true, action = clap::ArgAction::Append)]
        recipient: Vec<String>,

        // owner private key file
        #[arg(long)]
        private_key: String,

        // requested lifetime in seconds
        #[arg(long)]
        lifetime: u64,

        // server address
        #[arg(long)]
        server: String,
    },

    //download and decrypt a file
    Fetch {
        // file ID
        #[arg(long)]
        id: String,

        // recipient private key file
        #[arg(long)]
        private_key: String,

        // output path for decrypted file
        #[arg(long)]
        output: String,

        // server address
        #[arg(long)]
        server: String,
    },

    // delete an uploaded file
    Delete {
        // file ID
        #[arg(long)]
        id: String,

        // owner private key file
        #[arg(long)]
        private_key: String,

        // server address
        #[arg(long)]
        server: String,
    },
}



fn run() -> Result<(), CliError> {

    let cli = Cli::parse();

    match cli.command {

        Commands::Keygen { private, public } => {

            println!("Generating key pair...");
            println!("Private key path: {}", private);
            println!("Public key path: {}", public);

        }

        Commands::Upload {
            file,
            recipient,
            private_key,
            lifetime,
            server,
        } => {

            println!("Uploading file: {}", file);

            for recipient in recipient {
                println!("Recipient: {}", recipient);
            }

            println!("Owner key: {}", private_key);
            println!("Requested lifetime: {} seconds", lifetime);
            println!("Server: {}", server);

        }

        Commands::Fetch {
            id,
            private_key,
            output,
            server,
        } => {

            println!("Fetching file: {}", id);
            println!("Private key: {}", private_key);
            println!("Output: {}", output);
            println!("Server: {}", server);

        }

        Commands::Delete {
            id,
            private_key,
            server,
        } => {

            println!("Deleting file: {}", id);
            println!("Owner key: {}", private_key);
            println!("Server: {}", server);

        }
    }

    Ok(())
}


fn main() {
    if let Err(err) = run() {
        eprintln!("Lockbox error: {}", err);
    }
}

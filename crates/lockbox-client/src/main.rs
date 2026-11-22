use clap::{Arg, Command};
use std::error::Error;


mod errors; //import error types defined in errors.rs
use errors::CliError;

// Convert standard file errors into CliError.
impl From<std::io::Error> for CliError {
    fn from(err: std::io::Error) -> Self {
        CliError::Io(err)
    }
}

//this is to be able to actually display the custom error types
impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::Io(err) => write!(f, "File error: {}", err),
            //CliError::Parse(msg) => write!(f, "Input error: {}", msg),
        }
    }
}

impl Error for CliError {} // tell rust that cliError is a standard error type


//main
fn run() -> Result<(), CliError> {//success = ok, failure reutrn a clierror

    let matches = Command::new("lockbox")
        .version("0.1.0")
        .about("Short-lived encrypted file sharing")
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //COMMAND CONFIG/////////////////////////////////////////////////////////////////////////////////////////////
        //keygen
        .subcommand(
            Command::new("keygen")
                .about("Generate a new key pair")
                .arg(
                    Arg::new("private")
                        .long("private")
                        .help("Output path for private key")
                        .required(true)
                )
                .arg(
                    Arg::new("public")
                        .long("public")
                        .help("Output path for public key")
                        .required(true)
                )
        )
        //upload
        .subcommand(
            Command::new("upload")
                .about("Encrypt and upload a file")
                .arg(
                    Arg::new("file")
                        .long("file")
                        .help("File to upload")
                        .required(true)
                )
                .arg(
                    Arg::new("recipient")
                        .long("recipient")
                        .help("Recipient public key file")
                        .required(true)
                        .action(clap::ArgAction::Append)
                )
                .arg(
                    Arg::new("private-key")
                        .long("private-key")
                        .help("Owner private key file")
                        .required(true)
                )
                .arg(
                    Arg::new("lifetime")
                        .long("lifetime")
                        .help("Requested lifetime in seconds")
                        .value_parser(clap::value_parser!(u64))//convert string to int in cli
                        .required(true)
                )
                .arg(
                    Arg::new("server")
                        .long("server")
                        .help("Server address")
                        .required(true)
                )
        )
        //fetch
        .subcommand(
            Command::new("fetch")
                .about("Download and decrypt a file")
                .arg(
                    Arg::new("id")
                        .long("id")
                        .help("File ID")
                        .required(true)
                )
                .arg(
                    Arg::new("private-key")
                        .long("private-key")
                        .help("Recipient private key file")
                        .required(true)
                )
                .arg(
                    Arg::new("output")
                        .long("output")
                        .help("Output path for decrypted file")
                        .required(true)
                )
                .arg(
                    Arg::new("server")
                        .long("server")
                        .help("Server address")
                        .required(true)
                )
        )
        //delete
        .subcommand(
            Command::new("delete")
                .about("Delete an uploaded file")
                .arg(
                    Arg::new("id")
                        .long("id")
                        .help("File ID")
                        .required(true)
                )
                .arg(
                    Arg::new("private-key")
                        .long("private-key")
                        .help("Owner private key file")
                        .required(true)
                )
                .arg(
                    Arg::new("server")
                        .long("server")
                        .help("Server address")
                        .required(true)
                )
        )
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////
        .get_matches(); // string matching with input

    match matches.subcommand() {

        Some(("keygen", args)) => {
            let private = args.get_one::<String>("private").unwrap();
            let public = args.get_one::<String>("public").unwrap();

            println!("Generating key pair...");
            println!("Private key path: {}", private);
            println!("Public key path: {}", public);
        }

        Some(("upload", args)) => {
            let file = args.get_one::<String>("file").unwrap();
            let recipients = args.get_many::<String>("recipient").unwrap();
            let private_key = args.get_one::<String>("private-key").unwrap();
            let lifetime = args.get_one::<u64>("lifetime").unwrap(); //convert input to int
            let server = args.get_one::<String>("server").unwrap();

            println!("Uploading file: {}", file);

            for recipient in recipients {
                println!("Recipient: {}", recipient);
            }

            println!("Owner key: {}", private_key);
            println!("Requested lifetime: {} seconds", lifetime);
            println!("Server: {}", server);
        }

        Some(("fetch", args)) => {
            let id = args.get_one::<String>("id").unwrap();
            let private_key = args.get_one::<String>("private-key").unwrap();
            let output = args.get_one::<String>("output").unwrap();
            let server = args.get_one::<String>("server").unwrap();

            println!("Fetching file: {}", id);
            println!("Private key: {}", private_key);
            println!("Output: {}", output);
            println!("Server: {}", server);
        }

        Some(("delete", args)) => {
            let id = args.get_one::<String>("id").unwrap();
            let private_key = args.get_one::<String>("private-key").unwrap();
            let server = args.get_one::<String>("server").unwrap();

            println!("Deleting file: {}", id);
            println!("Owner key: {}", private_key);
            println!("Server: {}", server);
        }

        _ => {println!("unknown command")}//else if no matches, do nothing/defualt case
    }
        

    Ok(()) //if succeeds return ok

}

//entry point.
fn main() {
    //if error run
    if let Err(err) = run() { 
        eprintln!("Lockbox error: {}", err);
    }
}
       


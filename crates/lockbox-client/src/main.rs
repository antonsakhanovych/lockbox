mod commands;

use std::process::ExitCode;
use std::time::Duration;

const USAGE: &str = "Usage:
  lockbox-client keygen <secret-key> <public-key>
  lockbox-client upload <server> <owner-secret-key> <file> <recipient-public-key>...
  lockbox-client fetch <server> <recipient-secret-key> <file-id> <output>
  lockbox-client delete <server> <owner-secret-key> <file-id>";

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.is_empty() || args == ["--help"] || args == ["-h"] {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }

    match tokio::time::timeout(Duration::from_secs(60), run(&args)).await {
        Ok(Ok(())) => ExitCode::SUCCESS,
        Ok(Err(error)) => {
            eprintln!("lockbox: {error}");
            ExitCode::FAILURE
        }
        Err(_) => {
            eprintln!("lockbox: command timed out");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: &[String]) -> commands::Result<()> {
    let command = args[0].as_str();

    if command == "keygen" && args.len() == 3 {
        commands::keygen(&args[1], &args[2])
    } else if command == "upload" && args.len() >= 5 {
        commands::upload(&args[1], &args[2], &args[3], &args[4..]).await
    } else if command == "fetch" && args.len() == 5 {
        commands::fetch(&args[1], &args[2], args[3].parse()?, &args[4]).await
    } else if command == "delete" && args.len() == 4 {
        commands::delete(&args[1], &args[2], args[3].parse()?).await
    } else {
        Err(USAGE.into())
    }
}

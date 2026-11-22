//defining different custom error types
//recipient's public key is invalid
//file is larger than Lockbox's 64 MiB limit
//still working on ideas maybe encryption related

#[derive(Debug)]
pub enum CliError {
    Io(std::io::Error),
    //Parse(String),
   
}
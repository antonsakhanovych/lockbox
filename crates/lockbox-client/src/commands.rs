use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use lockbox_protocol::codec::{read_message, write_message};
use lockbox_protocol::crypto::envelope::{Envelope, MIN_CIPHERTEXT_LEN};
use lockbox_protocol::crypto::keys::{
    generate_keypair, load_public_key, load_secret_key, save_public_key, save_secret_key,
};
use lockbox_protocol::message::{MAX_CIPHERTEXT_LEN, MAX_LIFETIME_SECS};
use lockbox_protocol::transfer::{receive_fetch, send_upload};
use lockbox_protocol::{
    Challenge, FileHeader, FileId, ProtocolError, Purpose, Request, Response, SignedRequest,
};
use tokio::net::TcpStream;

pub type Result<T> = std::result::Result<T, Box<dyn Error>>;

pub fn keygen(secret: &str, public: &str) -> Result<()> {
    let key = generate_keypair();
    save_secret_key(Path::new(secret), &key)?;

    if let Err(error) = save_public_key(Path::new(public), &key.verifying_key()) {
        let _ = fs::remove_file(secret);
        return Err(error.into());
    }

    println!("Saved keys to {secret} and {public}");

    Ok(())
}

pub async fn upload(server: &str, secret: &str, path: &str, recipients: &[String]) -> Result<()> {
    let owner = load_secret_key(Path::new(secret))?;
    let recipients = recipients
        .iter()
        .map(|path| load_public_key(Path::new(path)))
        .collect::<std::result::Result<Vec<_>, _>>()?;

    let mut plaintext = Vec::new();
    File::open(path)?
        .take(MAX_CIPHERTEXT_LEN + 1)
        .read_to_end(&mut plaintext)?;

    if plaintext.len() as u64 > MAX_CIPHERTEXT_LEN - MIN_CIPHERTEXT_LEN as u64 {
        return Err("file exceeds the 64 MiB encrypted size limit".into());
    }

    let (envelope, ciphertext) =
        Envelope::encrypt_to_recipients(&plaintext, &recipients)?.into_parts();
    let header = FileHeader {
        envelope,
        ciphertext_len: ciphertext.len() as u64,
        expires_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + MAX_LIFETIME_SECS,
    };
    header.validate()?;

    let mut stream = TcpStream::connect(server).await?;
    let challenge =
        request_challenge(&mut stream, Request::BeginUpload, Purpose::Upload, None).await?;
    let file_id = challenge.file_id();

    write_message(
        &mut stream,
        &Request::Upload {
            proof: SignedRequest::answer(&challenge, &owner),
            header,
        },
    )
    .await?;
    expect(&mut stream, Response::ReadyForUpload).await?;
    send_upload(&mut stream, &ciphertext).await?;

    let Response::Uploaded {
        file_id: uploaded_id,
        expires_at,
    } = response(&mut stream).await?
    else {
        return Err(ProtocolError::UnexpectedMessage.into());
    };

    if uploaded_id != file_id {
        return Err(ProtocolError::ChallengeMismatch.into());
    }

    println!("{file_id}");
    eprintln!("Expires at {expires_at} (Unix seconds)");

    Ok(())
}

pub async fn fetch(server: &str, secret: &str, file_id: FileId, output: &str) -> Result<()> {
    let key = load_secret_key(Path::new(secret))?;
    let mut stream = TcpStream::connect(server).await?;
    let challenge = request_challenge(
        &mut stream,
        Request::BeginFetch { file_id },
        Purpose::Fetch,
        Some(file_id),
    )
    .await?;

    write_message(
        &mut stream,
        &Request::Fetch(SignedRequest::answer(&challenge, &key)),
    )
    .await?;
    let Response::FetchReady(header) = response(&mut stream).await? else {
        return Err(ProtocolError::UnexpectedMessage.into());
    };
    header.validate()?;

    let mut ciphertext = Vec::new();
    receive_fetch(&mut stream, &mut ciphertext, header.ciphertext_len).await?;
    let plaintext = header.recipient.decrypt(&key, &ciphertext)?;

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    if let Err(error) = file.write_all(&plaintext) {
        drop(file);
        let _ = fs::remove_file(output);
        return Err(error.into());
    }

    println!("Saved {output}");

    Ok(())
}

pub async fn delete(server: &str, secret: &str, file_id: FileId) -> Result<()> {
    let key = load_secret_key(Path::new(secret))?;
    let mut stream = TcpStream::connect(server).await?;
    let challenge = request_challenge(
        &mut stream,
        Request::BeginDelete { file_id },
        Purpose::Delete,
        Some(file_id),
    )
    .await?;

    write_message(
        &mut stream,
        &Request::Delete(SignedRequest::answer(&challenge, &key)),
    )
    .await?;
    expect(&mut stream, Response::Deleted).await?;

    println!("Deleted {file_id}");

    Ok(())
}

async fn request_challenge(
    stream: &mut TcpStream,
    request: Request,
    purpose: Purpose,
    file_id: Option<FileId>,
) -> std::result::Result<Challenge, ProtocolError> {
    write_message(stream, &request).await?;

    let Response::Challenge(challenge) = response(stream).await? else {
        return Err(ProtocolError::UnexpectedMessage);
    };

    if challenge.purpose() != purpose || file_id.is_some_and(|id| id != challenge.file_id()) {
        return Err(ProtocolError::ChallengeMismatch);
    }

    Ok(challenge)
}

async fn expect(
    stream: &mut TcpStream,
    expected: Response,
) -> std::result::Result<(), ProtocolError> {
    if response(stream).await? != expected {
        return Err(ProtocolError::UnexpectedMessage);
    }

    Ok(())
}

async fn response(stream: &mut TcpStream) -> std::result::Result<Response, ProtocolError> {
    match read_message(stream).await? {
        Response::Error(code) => Err(ProtocolError::Remote(code)),
        response => Ok(response),
    }
}

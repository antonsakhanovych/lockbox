#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use ed25519_dalek::{
    PUBLIC_KEY_LENGTH, SigningKey, VerifyingKey,
    pkcs8::{
        DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey,
        spki::der::pem::LineEnding,
    },
};

use crate::crypto::{CryptoError, Result};

const PUBLIC_FILE_MODE: u32 = 0o644;
const SECRET_FILE_MODE: u32 = 0o600;

pub fn generate_keypair() -> SigningKey {
    let mut csprng = rand::rng();
    SigningKey::generate(&mut csprng)
}

pub fn encode_public_key(key: &VerifyingKey) -> String {
    BASE64_STANDARD.encode(key)
}

pub fn decode_public_key(text: &str) -> Result<VerifyingKey> {
    let text = text.trim();
    let decoded = BASE64_STANDARD.decode(text)?;
    let bytes = <[u8; PUBLIC_KEY_LENGTH]>::try_from(decoded.as_slice()).map_err(|_| {
        CryptoError::WrongLength {
            expected: PUBLIC_KEY_LENGTH,
            actual: decoded.len(),
        }
    })?;
    let vkey = VerifyingKey::from_bytes(&bytes)?;
    Ok(vkey)
}

pub fn load_public_key(path: &Path) -> Result<VerifyingKey> {
    let pem = read_file(path)?;
    Ok(VerifyingKey::from_public_key_pem(&pem)?)
}

pub fn save_public_key(path: &Path, key: &VerifyingKey) -> Result<()> {
    let pem = key.to_public_key_pem(LineEnding::LF)?;
    write_new_file(path, &pem, PUBLIC_FILE_MODE)
}

pub fn load_secret_key(path: &Path) -> Result<SigningKey> {
    let pem = read_file(path)?;
    Ok(SigningKey::from_pkcs8_pem(&pem)?)
}

pub fn save_secret_key(path: &Path, key: &SigningKey) -> Result<()> {
    let pem = key.to_pkcs8_pem(LineEnding::LF)?;
    write_new_file(path, &pem, SECRET_FILE_MODE)
}

fn read_file(path: &Path) -> Result<String> {
    fs::read_to_string(path).map_err(|source| CryptoError::FileIo {
        path: path.to_path_buf(),
        source,
    })
}

fn write_new_file(path: &Path, contents: &str, mode: u32) -> Result<()> {
    let io_error = |source| CryptoError::FileIo {
        path: path.to_path_buf(),
        source,
    };
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(mode);
    #[cfg(not(unix))]
    let _ = mode;
    let mut file = options.open(path).map_err(io_error)?;
    file.write_all(contents.as_bytes()).map_err(io_error)
}

use std::os::unix::fs::PermissionsExt;

use lockbox_protocol::crypto::CryptoError;
use lockbox_protocol::crypto::keys::{
    generate_keypair, load_public_key, load_secret_key, save_public_key, save_secret_key,
};

#[test]
fn secret_key_round_trips_through_a_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("id.pem");
    let key = generate_keypair();
    save_secret_key(&path, &key).unwrap();
    let loaded = load_secret_key(&path).unwrap();
    assert_eq!(loaded.to_bytes(), key.to_bytes());
    assert_eq!(loaded.verifying_key(), key.verifying_key());
}

#[test]
fn public_key_round_trips_through_a_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("id.pub.pem");
    let public = generate_keypair().verifying_key();
    save_public_key(&path, &public).unwrap();
    assert_eq!(load_public_key(&path).unwrap(), public);
}

#[test]
fn secret_key_file_is_standard_pkcs8_pem() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("id.pem");
    save_secret_key(&path, &generate_keypair()).unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.starts_with("-----BEGIN PRIVATE KEY-----\n"));
    assert!(text.ends_with("-----END PRIVATE KEY-----\n"));
}

#[test]
fn public_key_file_is_standard_spki_pem() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("id.pub.pem");
    save_public_key(&path, &generate_keypair().verifying_key()).unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.starts_with("-----BEGIN PUBLIC KEY-----\n"));
    assert!(text.ends_with("-----END PUBLIC KEY-----\n"));
}

#[test]
fn secret_key_file_is_only_accessible_by_its_owner() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("id.pem");
    save_secret_key(&path, &generate_keypair()).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn saving_a_secret_key_never_overwrites_an_existing_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("id.pem");
    let original = generate_keypair();
    save_secret_key(&path, &original).unwrap();
    let before = std::fs::read(&path).unwrap();

    assert!(matches!(
        save_secret_key(&path, &generate_keypair()),
        Err(CryptoError::FileIo { .. })
    ));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(
        load_secret_key(&path).unwrap().to_bytes(),
        original.to_bytes()
    );
}

#[test]
fn saving_a_public_key_never_overwrites_an_existing_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("id.pub.pem");
    let original = generate_keypair().verifying_key();
    save_public_key(&path, &original).unwrap();

    assert!(matches!(
        save_public_key(&path, &generate_keypair().verifying_key()),
        Err(CryptoError::FileIo { .. })
    ));
    assert_eq!(load_public_key(&path).unwrap(), original);
}

#[test]
fn saving_into_a_missing_directory_reports_the_path() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing").join("id.pem");
    match save_secret_key(&path, &generate_keypair()) {
        Err(CryptoError::FileIo { path: reported, .. }) => assert_eq!(reported, path),
        other => panic!("unexpected result: {other:?}"),
    }
}

#[test]
fn loading_a_missing_file_reports_the_path() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing.pem");
    match load_secret_key(&path) {
        Err(CryptoError::FileIo { path: reported, .. }) => assert_eq!(reported, path),
        other => panic!("unexpected result: {other:?}"),
    }
    assert!(matches!(
        load_public_key(&path),
        Err(CryptoError::FileIo { .. })
    ));
}

#[test]
fn loading_garbage_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("garbage.pem");
    std::fs::write(&path, "this is not a key\n").unwrap();
    assert!(matches!(load_secret_key(&path), Err(CryptoError::Pkcs8(_))));
    assert!(matches!(load_public_key(&path), Err(CryptoError::Spki(_))));
}

#[test]
fn a_public_key_file_cannot_be_loaded_as_a_secret_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("id.pub.pem");
    save_public_key(&path, &generate_keypair().verifying_key()).unwrap();
    assert!(load_secret_key(&path).is_err());
}

#[test]
fn a_secret_key_file_cannot_be_loaded_as_a_public_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("id.pem");
    save_secret_key(&path, &generate_keypair()).unwrap();
    assert!(load_public_key(&path).is_err());
}

#[test]
fn a_truncated_secret_key_file_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("id.pem");
    save_secret_key(&path, &generate_keypair()).unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, &text[..text.len() / 2]).unwrap();
    assert!(load_secret_key(&path).is_err());
}

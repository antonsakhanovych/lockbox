use std::collections::HashSet;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use lockbox_crypto::keys::{decode_public_key, encode_public_key, generate_keypair};
use lockbox_crypto::{CryptoError, SigningKey};

#[test]
fn two_generated_keys_differ() {
    let first = generate_keypair();
    let second = generate_keypair();
    assert_ne!(first.verifying_key(), second.verifying_key());
}

#[test]
fn many_generated_keys_are_all_distinct() {
    let public_keys: HashSet<[u8; 32]> = (0..100)
        .map(|_| generate_keypair().verifying_key().to_bytes())
        .collect();
    assert_eq!(public_keys.len(), 100);
}

#[test]
fn public_key_is_derived_from_the_secret_seed() {
    let key = generate_keypair();
    let rebuilt = SigningKey::from_bytes(&key.to_bytes());
    assert_eq!(rebuilt.verifying_key(), key.verifying_key());
}

#[test]
fn public_key_round_trips_through_text() {
    let public = generate_keypair().verifying_key();
    let text = encode_public_key(&public);
    assert_eq!(decode_public_key(&text).unwrap(), public);
}

#[test]
fn encoded_public_key_is_padded_standard_base64_of_32_bytes() {
    let public = generate_keypair().verifying_key();
    let text = encode_public_key(&public);
    assert_eq!(text.len(), 44);
    assert_eq!(STANDARD.decode(&text).unwrap(), public.as_bytes());
}

#[test]
fn surrounding_whitespace_is_ignored() {
    let public = generate_keypair().verifying_key();
    let text = format!("  {}\n", encode_public_key(&public));
    assert_eq!(decode_public_key(&text).unwrap(), public);
}

#[test]
fn text_that_is_too_short_reports_both_lengths() {
    match decode_public_key("AAAA") {
        Err(CryptoError::WrongLength { expected, actual }) => {
            assert_eq!(expected, 32);
            assert_eq!(actual, 3);
        }
        other => panic!("unexpected result: {other:?}"),
    }
}

#[test]
fn text_that_is_too_long_reports_both_lengths() {
    match decode_public_key(&"AAAA".repeat(11)) {
        Err(CryptoError::WrongLength { expected, actual }) => {
            assert_eq!(expected, 32);
            assert_eq!(actual, 33);
        }
        other => panic!("unexpected result: {other:?}"),
    }
}

#[test]
fn text_that_is_not_base64_is_rejected() {
    assert!(matches!(
        decode_public_key("not base64!"),
        Err(CryptoError::Base64(_))
    ));
}

#[test]
fn empty_text_is_rejected() {
    assert!(matches!(
        decode_public_key(""),
        Err(CryptoError::WrongLength { actual: 0, .. })
    ));
}

#[test]
fn thirty_two_bytes_that_are_not_a_curve_point_are_rejected() {
    let mut bytes = [0u8; 32];
    bytes[0] = 2;
    let text = STANDARD.encode(bytes);
    assert!(matches!(
        decode_public_key(&text),
        Err(CryptoError::InvalidKey(_))
    ));
}

use std::collections::HashSet;

use lockbox_crypto::SigningKey;
use lockbox_crypto::keys::generate_keypair;

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

use ed25519_dalek::SigningKey;

pub fn generate_keypair() -> SigningKey {
    let mut csprng = rand::rng();
    SigningKey::generate(&mut csprng)
}

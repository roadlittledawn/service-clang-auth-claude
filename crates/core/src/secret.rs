//! Opaque random tokens and their hashes.
//!
//! Session tokens, invite tokens and the admin key are all "bearer secrets":
//! whoever holds them is trusted. We only ever store `sha256(secret)` so that a
//! leaked database dump cannot be replayed.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Generate `bytes` random bytes from the OS CSPRNG, base64url-encoded.
pub fn random_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    OsRng.fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

/// 32 random bytes (256 bits): used for sessions and invites.
pub fn new_token() -> String {
    random_token(32)
}

/// Lowercase hex SHA-256 of the input.
pub fn sha256_hex(input: &str) -> String {
    hex::encode(Sha256::digest(input.as_bytes()))
}

/// Constant-time check that `sha256(presented) == expected_hex`.
pub fn verify_sha256_hex(presented: &str, expected_hex: &str) -> bool {
    let actual: [u8; 32] = Sha256::digest(presented.as_bytes()).into();
    match hex::decode(expected_hex.trim()) {
        Ok(expected) => expected.len() == actual.len() && bool::from(actual[..].ct_eq(&expected)),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_long_and_unique() {
        let a = new_token();
        let b = new_token();
        assert_ne!(a, b);
        assert_eq!(a.len(), 43); // 32 bytes base64url, no padding
    }

    #[test]
    fn verify_hash() {
        let h = sha256_hex("dev-admin-key");
        assert!(verify_sha256_hex("dev-admin-key", &h));
        assert!(!verify_sha256_hex("dev-admin-kez", &h));
        assert!(!verify_sha256_hex("dev-admin-key", "not-hex"));
    }
}

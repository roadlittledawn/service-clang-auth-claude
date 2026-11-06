//! Password hashing (Argon2id) and the password policy.
//!
//! Hashing is deliberately slow and memory-hard so that a stolen database
//! cannot be brute-forced cheaply. Verification uses the library's
//! constant-time comparison.

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use std::sync::OnceLock;

use crate::{Error, Result};

pub const MIN_LEN: usize = 12;
pub const MAX_LEN: usize = 128;

/// OWASP minimums for Argon2id: 19 MiB memory, 2 iterations, 1 lane.
pub const MIN_M_KIB: u32 = 19 * 1024;
pub const MIN_T: u32 = 2;
pub const MIN_P: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl Default for HashParams {
    fn default() -> Self {
        Self {
            m_kib: MIN_M_KIB,
            t: MIN_T,
            p: MIN_P,
        }
    }
}

impl HashParams {
    /// Build params, refusing anything below the OWASP minimums.
    pub fn new(m_kib: u32, t: u32, p: u32) -> Result<Self> {
        if m_kib < MIN_M_KIB || t < MIN_T || p < MIN_P {
            return Err(Error::Invalid(format!(
                "argon2 params below minimum (m>={MIN_M_KIB} KiB, t>={MIN_T}, p>={MIN_P})"
            )));
        }
        Ok(Self { m_kib, t, p })
    }

    fn argon2(&self) -> Argon2<'static> {
        let params = Params::new(self.m_kib, self.t, self.p, None).expect("valid argon2 params");
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
    }
}

/// Check the password policy: 12..=128 characters, no composition rules.
pub fn check_policy(password: &str) -> Result<()> {
    let len = password.chars().count();
    if len < MIN_LEN {
        return Err(Error::Invalid(format!(
            "Password must be at least {MIN_LEN} characters."
        )));
    }
    if len > MAX_LEN {
        return Err(Error::Invalid(format!(
            "Password must be at most {MAX_LEN} characters."
        )));
    }
    Ok(())
}

/// Hash a password into a PHC string (`$argon2id$v=19$m=...`).
pub fn hash(password: &str, params: HashParams) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    params
        .argon2()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| Error::Hash)
}

/// Verify a password against a stored PHC hash. Parameters are read from the
/// hash itself, so old hashes keep working after params are raised.
pub fn verify(password: &str, phc: &str) -> bool {
    match PasswordHash::new(phc) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// Burn the same amount of time as a real verification. Used when the email
/// is unknown or the account has no password, so response timing does not
/// reveal whether an account exists.
pub fn verify_dummy(password: &str, params: HashParams) {
    static DUMMY: OnceLock<String> = OnceLock::new();
    let phc = DUMMY.get_or_init(|| hash("dummy-password-for-timing", params).expect("hash dummy"));
    let _ = verify(password, phc);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy() {
        assert!(check_policy("short").is_err());
        assert!(check_policy("elevenchars").is_err());
        assert!(check_policy("twelve chars").is_ok());
        assert!(check_policy(&"x".repeat(128)).is_ok());
        assert!(check_policy(&"x".repeat(129)).is_err());
        // Characters, not bytes.
        assert!(check_policy(&"é".repeat(12)).is_ok());
    }

    #[test]
    fn hash_and_verify() {
        let h = hash("correct horse battery", HashParams::default()).unwrap();
        assert!(h.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        assert!(verify("correct horse battery", &h));
        assert!(!verify("wrong horse battery", &h));
        assert!(!verify("anything", "not-a-hash"));
    }

    #[test]
    fn rejects_weak_params() {
        assert!(HashParams::new(1024, 2, 1).is_err());
        assert!(HashParams::new(MIN_M_KIB, 1, 1).is_err());
        assert!(HashParams::new(64 * 1024, 3, 1).is_ok());
    }
}
